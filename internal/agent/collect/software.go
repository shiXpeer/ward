package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// HomebrewFormulaSnapshot inventories only the installed kegs of one formula.
func HomebrewFormulaSnapshot(prefix, name string) (inventory.Snapshot, error) {
	var snapshot inventory.Snapshot
	snapshot.Host.OS = "darwin"
	if (prefix != "/opt/homebrew" && prefix != "/usr/local") || name == "" ||
		strings.HasPrefix(name, "-") || name == "." || name == ".." || filepath.Base(name) != name {
		return snapshot, fmt.Errorf("invalid Homebrew formula or prefix")
	}
	cellar := filepath.Join(prefix, "Cellar")
	entries, err := os.ReadDir(filepath.Join(cellar, name))
	if err != nil {
		return snapshot, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		provenance, version, bottle := brewReceipt(cellar, name, entry.Name())
		if provenance != "homebrew/core" || version == "" {
			return snapshot, fmt.Errorf("cannot verify Homebrew receipt for %s", entry.Name())
		}
		snapshot.Packages = append(snapshot.Packages, inventory.Package{
			Manager: "homebrew-formula", Name: name, Version: entry.Name(), Status: "installed",
			Provenance: provenance, UpstreamVersion: version, HomebrewBottle: bottle,
		})
	}
	if len(snapshot.Packages) == 0 {
		return snapshot, fmt.Errorf("no installed Homebrew kegs found")
	}
	return snapshot, nil
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
					p.Provenance, p.UpstreamVersion, p.HomebrewBottle = brewReceipt(cellar, f[0], v)
				}
				s.Packages = append(s.Packages, p)
			}
		}
	}
}
func (h Host) applications(ctx context.Context, s *inventory.Snapshot) {
	dirs := []string{"/Applications", "/System/Applications"}
	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	} else {
		home = ""
	}
	h.applicationDirs(ctx, s, dirs)
	if home != "" {
		h.launchedApplications(ctx, s, home)
	}
	s.AddNote(inventory.NotChecked, "application-scope", "only /Applications, /System/Applications and user Applications (one category level) are walked; apps this account has opened elsewhere are added from Spotlight. Copies in Library, node_modules, DerivedData and dist, and other volumes, are not treated as installed applications")
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
				app, e := h.readApplication(ctx, path, d.Name())
				if e != nil {
					detail := "an application plist could not be parsed"
					if errors.Is(e, errApplicationMetadata) {
						detail = "application metadata exceeds field limits"
					}
					s.AddNote(inventory.Unavailable, "applications", detail)
					return filepath.SkipDir
				}
				s.Applications = append(s.Applications, app)
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
}

var errApplicationMetadata = errors.New("application metadata exceeds field limits")

type bundleInfo struct {
	Name    string `json:"CFBundleName"`
	ID      string `json:"CFBundleIdentifier"`
	Version string `json:"CFBundleShortVersionString"`
	Build   string `json:"CFBundleVersion"`
}

func (h Host) readApplication(ctx context.Context, path, filename string) (inventory.Application, error) {
	data, err := h.commandLimit(ctx, 1<<20, "plutil", "-convert", "json", "-o", "-", filepath.Join(path, "Contents", "Info.plist"))
	var info bundleInfo
	if err != nil || json.Unmarshal(data, &info) != nil {
		return inventory.Application{}, errors.New("application plist could not be parsed")
	}
	if len(info.Name) > 512 || len(info.ID) > 512 || len(info.Version) > 512 || len(info.Build) > 512 {
		return inventory.Application{}, errApplicationMetadata
	}
	kind := "release"
	version := info.Version
	if version == "" {
		version = info.Build
		kind = "build"
	}
	name := info.Name
	if name == "" {
		name = strings.TrimSuffix(filename, ".app")
	}
	return inventory.Application{Name: name, Version: version, Identifier: info.ID, VersionKind: kind}, nil
}

// launchedApplications adds bundles the account has actually opened that live
// outside the walked folders. A preferences file is the evidence of a launch.
// Build trees and nested helpers are left out so a source checkout is not an install.
func (h Host) launchedApplications(ctx context.Context, s *inventory.Snapshot, home string) {
	out, err := h.commandLimit(ctx, 2<<20, "mdfind", "kMDItemContentTypeTree == 'com.apple.application-bundle'")
	if err != nil {
		s.AddNote(inventory.Unavailable, "applications", "apps outside the standard folders could not be listed")
		return
	}
	known := map[string]struct{}{}
	for _, app := range s.Applications {
		if app.Identifier != "" {
			known[app.Identifier] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		path := applicationBundlePath(line)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		if skippedApplicationPath(path, home) {
			continue
		}
		if len(s.Applications) >= maxApplications {
			s.AddNote(inventory.Truncated, "applications", "application bundle limit reached")
			return
		}
		app, e := h.readApplication(ctx, path, filepath.Base(path))
		if e != nil || !validBundleID(app.Identifier) {
			continue
		}
		if _, ok := known[app.Identifier]; ok {
			continue
		}
		prefs := filepath.Join(home, "Library", "Preferences", app.Identifier+".plist")
		info, statErr := os.Stat(prefs)
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		known[app.Identifier] = struct{}{}
		s.Applications = append(s.Applications, app)
	}
}

func applicationBundlePath(raw string) string {
	raw = strings.TrimSpace(raw)
	idx := strings.Index(raw, ".app")
	if idx < 0 || !strings.HasPrefix(raw, "/") {
		return ""
	}
	end := idx + len(".app")
	if end != len(raw) && raw[end] != '/' {
		return ""
	}
	path := filepath.Clean(raw[:end])
	if strings.Contains(path, "..") || strings.Count(path, ".app") != 1 {
		return ""
	}
	return path
}

func skippedApplicationPath(path, home string) bool {
	for _, root := range []string{"/Applications/", "/System/"} {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	if home != "" && strings.HasPrefix(path, filepath.Clean(home)+"/Applications/") {
		return true
	}
	if strings.Contains(path, ".framework/") {
		return true
	}
	switch {
	case strings.Contains(path, "/Library/"),
		strings.Contains(path, "/node_modules/"),
		strings.Contains(path, "/DerivedData/"),
		strings.Contains(path, "/dist/"):
		return true
	default:
		return false
	}
}

func validBundleID(id string) bool {
	if len(id) < 3 || len(id) > 200 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '.' || r == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// Trust the installed receipt, not the current remote formula metadata. Source
// version excludes Homebrew revisions; HEAD/custom taps never map implicitly.
func brewReceipt(cellar, name, version string) (string, string, string) {
	if filepath.Base(name) != name || filepath.Base(version) != version || name == "." || version == "." {
		return "", "", ""
	}
	f, err := os.Open(filepath.Join(cellar, name, version, "INSTALL_RECEIPT.json"))
	if err != nil {
		return "", "", ""
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil || len(raw) >= 1<<20 {
		return "", "", ""
	}
	var r struct {
		PouredFromBottle bool `json:"poured_from_bottle"`
		BuiltAsBottle    bool `json:"built_as_bottle"`
		Arch             string
		BuiltOn          struct {
			OSVersion string `json:"os_version"`
		} `json:"built_on"`
		Source struct {
			Tap      string
			Spec     string
			Versions struct{ Stable string }
		}
	}
	if json.Unmarshal(raw, &r) != nil || r.Source.Spec != "stable" || r.Source.Tap != "homebrew/core" || len(r.Source.Versions.Stable) > 512 {
		return "", "", ""
	}
	stable := r.Source.Versions.Stable
	if version != stable {
		suffix, ok := strings.CutPrefix(version, stable+"_")
		if !ok || suffix == "" || strings.Trim(suffix, "0123456789") != "" {
			return "", "", ""
		}
	}
	bottle := ""
	if r.PouredFromBottle && r.BuiltAsBottle && r.Arch == "arm64" &&
		(r.BuiltOn.OSVersion == "macOS 27" || r.BuiltOn.OSVersion == "macOS 27.0") {
		bottle = "arm64_golden_gate"
	}
	return r.Source.Tap, stable, bottle
}
