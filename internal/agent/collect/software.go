package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"shixpeer.com/ward/pkg/inventory"
)

const maxPackages = 50000
const maxApplications = 3000

// SoftwareSnapshot performs read-only local probes. It never executes installed
// applications or asks a package manager to update, install or query the network.
func (h Host) SoftwareSnapshot(ctx context.Context) (inventory.Snapshot, error) {
	s, err := h.Snapshot(ctx)
	if err != nil {
		return s, err
	}
	notes := s.Coverage[:0]
	for _, n := range s.Coverage {
		if n.Source != "packages" && n.Source != "applications" && !(runtime.GOOS == "darwin" && n.Source == "os-release") {
			notes = append(notes, n)
		}
	}
	s.Coverage = notes
	switch runtime.GOOS {
	case "darwin":
		h.brew(ctx, &s)
		h.applications(ctx, &s)
	case "linux":
		if s.Host.Release["ID"] == "debian" || s.Host.Release["ID"] == "ubuntu" {
			h.dpkg(ctx, &s)
			h.runningKernel(ctx, &s)
		} else {
			s.AddNote(inventory.NotChecked, "packages", "only Debian/Ubuntu package inventory is supported on Linux")
		}
		s.AddNote(inventory.NotChecked, "applications", "applications outside the system package manager were not inspected")
	default:
		s.AddNote(inventory.NotChecked, "packages", "unsupported operating system")
		s.AddNote(inventory.NotChecked, "applications", "unsupported operating system")
	}
	h.runtimeState(ctx, &s)
	h.globalDependencies(ctx, &s)
	sort.Slice(s.Dependencies, func(i, j int) bool {
		a, b := s.Dependencies[i], s.Dependencies[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return s, ctx.Err()
}
func (h Host) dpkg(ctx context.Context, s *inventory.Snapshot) {
	const format = "${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n"
	out, err := h.commandLimit(ctx, 16<<20, "dpkg-query", "-W", "-f="+format)
	if err != nil {
		s.AddNote(inventory.Unavailable, "packages", "dpkg-query failed or exceeded its output/time limit")
		return
	}
	packages, err := parseDPKG(string(out))
	if err != nil {
		s.AddNote(inventory.Unavailable, "packages", "invalid or excessive dpkg-query output")
		return
	}
	s.Packages = packages
}
func parseDPKG(text string) ([]inventory.Package, error) {
	out := []inventory.Package{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return nil, errors.New("invalid dpkg fields")
		}
		if f[0] != "installed" {
			continue
		}
		if f[1] == "" || f[2] == "" {
			return nil, errors.New("missing package identity")
		}
		name := strings.Split(f[1], ":")[0]
		source, version := f[4], f[5]
		if source == "" {
			source = name
		}
		if version == "" {
			version = f[2]
		}
		out = append(out, inventory.Package{Manager: "dpkg", Name: name, Version: f[2], Architecture: f[3], SourceName: source, SourceVersion: version, Status: "installed"})
		if len(out) > maxPackages {
			return nil, errors.New("too many packages")
		}
	}
	return out, nil
}
func (h Host) brew(ctx context.Context, s *inventory.Snapshot) {
	cellar := ""
	if raw, err := h.commandLimit(ctx, 4096, "brew", "--cellar"); err == nil {
		value := strings.TrimSpace(string(raw))
		if filepath.IsAbs(value) {
			cellar = value
		}
	}

	for _, kind := range []string{"formula", "cask"} {
		out, err := h.commandLimit(ctx, 4<<20, "brew", "list", "--versions", "--"+kind)
		if err != nil {
			s.AddNote(inventory.Unavailable, "homebrew-"+kind, "local brew inventory failed, is unavailable, or exceeded its limit")
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			for _, v := range f[1:] {
				if len(s.Packages) >= maxPackages {
					s.AddNote(inventory.Truncated, "packages", "package limit reached")
					return
				}
				p := inventory.Package{Manager: "homebrew-" + kind, Name: f[0], Version: v, Status: "installed"}
				if kind == "formula" && cellar != "" {
					p.Provenance, p.UpstreamVersion = brewReceipt(cellar, f[0], v)
				}
				s.Packages = append(s.Packages, p)
			}
		}
	}
}
func (h Host) applications(ctx context.Context, s *inventory.Snapshot) {
	dirs := []string{"/Applications", "/System/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	h.applicationDirs(ctx, s, dirs)
}
func (h Host) applicationDirs(ctx context.Context, s *inventory.Snapshot, dirs []string) {
	inspected := 0
	for _, root := range dirs {
		// Only direct bundles and one category directory (e.g. Utilities); do not
		// recurse inside applications, symlinks, user files or mounted volumes.
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) && path == root {
					return nil
				}
				s.AddNote(inventory.Unavailable, "applications", "an application directory could not be read")
				return filepath.SkipDir
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			if strings.HasSuffix(d.Name(), ".app") {
				inspected++
				if inspected > maxApplications {
					s.AddNote(inventory.Truncated, "applications", "application bundle limit reached")
					return filepath.SkipAll
				}
				data, e := h.commandLimit(ctx, 1<<20, "plutil", "-convert", "json", "-o", "-", filepath.Join(path, "Contents", "Info.plist"))
				var p struct {
					Name    string `json:"CFBundleName"`
					ID      string `json:"CFBundleIdentifier"`
					Version string `json:"CFBundleShortVersionString"`
					Build   string `json:"CFBundleVersion"`
				}
				if e != nil || json.Unmarshal(data, &p) != nil {
					s.AddNote(inventory.Unavailable, "applications", "an application plist could not be parsed")
					return filepath.SkipDir
				}
				if len(p.Name) > 512 || len(p.ID) > 512 || len(p.Version) > 512 || len(p.Build) > 512 {
					s.AddNote(inventory.Unavailable, "applications", "application metadata exceeds field limits")
					return filepath.SkipDir
				}
				kind := "release"
				if p.Version == "" {
					p.Version = p.Build
					kind = "build"
				}
				if p.Name == "" {
					p.Name = strings.TrimSuffix(d.Name(), ".app")
				}
				s.Applications = append(s.Applications, inventory.Application{Name: p.Name, Version: p.Version, Identifier: p.ID, VersionKind: kind})
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(filepath.Separator)) >= 1 {
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil && !errors.Is(err, io.EOF) {
			s.AddNote(inventory.Unavailable, "applications", "application enumeration failed")
		}
	}
	s.AddNote(inventory.NotChecked, "application-scope", "only /Applications, /System/Applications and user Applications (one category level) were inspected; nested and other volumes excluded")
}

// Trust the installed receipt, not the current remote formula metadata. Source
// version excludes Homebrew revisions; HEAD/custom taps never map implicitly.
func brewReceipt(cellar, name, version string) (string, string) {
	if filepath.Base(name) != name || filepath.Base(version) != version || name == "." || version == "." {
		return "", ""
	}
	f, err := os.Open(filepath.Join(cellar, name, version, "INSTALL_RECEIPT.json"))
	if err != nil {
		return "", ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil || len(raw) >= 1<<20 {
		return "", ""
	}
	var r struct {
		Source struct {
			Tap      string
			Spec     string
			Versions struct{ Stable string }
		}
	}
	if json.Unmarshal(raw, &r) != nil || r.Source.Spec != "stable" || r.Source.Tap != "homebrew/core" || len(r.Source.Versions.Stable) > 512 {
		return "", ""
	}
	stable := r.Source.Versions.Stable
	if version != stable {
		suffix, ok := strings.CutPrefix(version, stable+"_")
		if !ok || suffix == "" || strings.Trim(suffix, "0123456789") != "" {
			return "", ""
		}
	}
	return r.Source.Tap, stable
}
