package collect

import (
	"context"
	"io"
	"os"
	"regexp"
	"strings"

	"shixpeer.com/ward/internal/debversion"
	"shixpeer.com/ward/pkg/inventory"
)

var kernelABI = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)-(.+)$`)
var debianBuild = regexp.MustCompile(`\bDebian ([0-9][0-9A-Za-z.+:~_-]*)(?:[[:space:]]|$)`)
var builtUsing = regexp.MustCompile(`^(linux(?:-[a-z0-9.+-]+)?) \(= ([0-9A-Za-z.+:~_-]+)\)$`)

func (h Host) runningKernel(ctx context.Context, s *inventory.Snapshot) {
	fields := strings.Fields(s.Host.Uname)
	if len(fields) < 2 || fields[0] != "Linux" {
		return
	}
	k := &inventory.Kernel{Release: fields[1], Status: "UNRESOLVED"}
	s.RunningKernel = k
	if s.Host.Release["ID"] == "ubuntu" {
		if st, e := os.Stat("/var/run/reboot-required"); e == nil && st.Mode().IsRegular() {
			k.RebootRequired = true
			if f, err := os.Open("/var/run/reboot-required.pkgs"); err == nil {
				raw, e := io.ReadAll(io.LimitReader(f, 4097))
				f.Close()
				if e == nil && len(raw) <= 4096 {
					k.RebootPackages = rebootPackages(string(raw))
				}
			}

			s.AddNote(inventory.Unresolved, "kernel-reboot", "Ubuntu reports a pending reboot; the reason may be unrelated to the kernel")
		}
	}
	var image *inventory.Package
	for i := range s.Packages {
		p := &s.Packages[i]
		if p.Name == "linux-image-"+k.Release || p.Name == "linux-image-unsigned-"+k.Release {
			image = p
			break
		}
	}
	if image == nil {
		k.Detail = "running kernel has no corresponding installed image package"
		s.AddNote(inventory.Unresolved, "running-kernel", k.Detail)
		return
	}
	k.Package = image.Name
	k.SourceName = image.SourceName
	k.InstalledSourceVersion = image.SourceVersion
	if strings.HasPrefix(k.SourceName, "linux-signed") {
		raw, e := h.commandLimit(ctx, 16384, "dpkg-query", "-W", "-f=${Built-Using}", image.Name)
		k.SourceName = ""
		k.InstalledSourceVersion = ""
		if e == nil {
			for _, entry := range strings.Split(strings.TrimSpace(string(raw)), ",") {
				if m := builtUsing.FindStringSubmatch(strings.TrimSpace(entry)); len(m) > 0 && !strings.HasPrefix(m[1], "linux-signed") {
					k.SourceName = m[1]
					k.InstalledSourceVersion = m[2]
					break
				}
			}
		}
	}
	if k.SourceName == "" {
		k.Detail = "signed kernel lacks a supported Built-Using source identity"
		s.AddNote(inventory.Unresolved, "running-kernel", k.Detail)
		return
	}
	if s.Host.Release["ID"] == "ubuntu" {
		raw, e := os.ReadFile("/proc/version_signature")
		if e == nil && len(raw) <= 4096 {
			k.SourceVersion = ubuntuKernelVersion(k.Release, string(raw))
		}
	} else if s.Host.Release["ID"] == "debian" {
		if raw, e := h.commandLimit(ctx, 4096, "uname", "-v"); e == nil {
			if m := debianBuild.FindStringSubmatch(string(raw)); len(m) > 0 {
				k.SourceVersion = m[1]
			}
		}
	}
	if k.SourceVersion == "" {
		k.Detail = "loaded kernel source version is not verifiable from the supported build signature; installed package version is not substituted"
		s.AddNote(inventory.Unresolved, "running-kernel", k.Detail)
		return
	}
	if _, e := debversion.Compare(k.SourceVersion, k.SourceVersion); e != nil {
		k.SourceVersion = ""
		k.Detail = "unsupported running kernel version signature"
		s.AddNote(inventory.Unresolved, "running-kernel", k.Detail)
		return
	}

	k.Status = "IDENTIFIED"
	if n, e := debversion.Compare(k.SourceVersion, k.InstalledSourceVersion); e == nil && n < 0 {
		k.RebootRequired = true
		s.AddNote(inventory.Unresolved, "kernel-reboot", "installed kernel source is newer than the loaded kernel; schedule reboot and verify the new running kernel")
	}
}
func ubuntuKernelVersion(release, signature string) string {
	abi := kernelABI.FindStringSubmatch(release)
	f := strings.Fields(signature)
	if len(abi) == 0 || len(f) < 2 || f[0] != "Ubuntu" {
		return ""
	}
	version, ok := strings.CutSuffix(f[1], "-"+abi[2])
	if !ok || !strings.HasPrefix(version, abi[1]+".") {
		return ""
	}
	if _, e := debversion.Compare(version, version); e != nil {
		return ""
	}
	return version
}

var rebootPackageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9-]{1,32})?$`)

func rebootPackages(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Fields(raw) {
		if !seen[p] && rebootPackageName.MatchString(p) {
			seen[p] = true
			out = append(out, p)
			if len(out) == 32 {
				break
			}
		}
	}
	return out
}
