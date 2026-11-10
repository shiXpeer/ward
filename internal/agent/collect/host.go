// Package collect observes the local machine. Probes that are not implemented
// yet leave a NOT_CHECKED coverage note instead of an empty section that
// could be read as "nothing installed".
package collect

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"shixpeer.com/ward/internal/buildinfo"
	"strconv"
	"strings"
	"time"

	"shixpeer.com/ward/pkg/inventory"
)

var Version = buildinfo.Version

const osReleaseLimit = 1 << 20

// Command runs a local probe. Tests substitute it. Production uses a cleaned
// environment and stdout only, so tool errors are not copied into the snapshot.
type Command func(ctx context.Context, name string, args ...string) ([]byte, error)

type Host struct {
	DockerSnapshotPath string
	OSReleasePaths     []string
	Command            Command
}

var notChecked = []struct{ source, detail string }{
	{"packages", "package databases are not collected yet"},
	{"services", "service and process state is not collected yet"},
	{"listeners", "listening sockets are not collected yet"},
	{"applications", "application versions are not collected yet"},
	{"containers", "local containers are not collected yet"},
	{"dependencies", "lockfiles are not collected yet"},
}

var releaseKeys = map[string]struct{}{
	"ID": {}, "ID_LIKE": {}, "VERSION_ID": {}, "VERSION_CODENAME": {},
	"PRETTY_NAME": {}, "BUILD_ID": {},
}

var macKeys = map[string]struct{}{
	"ProductName": {}, "ProductVersion": {}, "BuildVersion": {},
}

func (h Host) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return inventory.Snapshot{}, err
	}
	snap := inventory.Snapshot{
		FormatVersion:    inventory.FormatVersion,
		Collector:        "shixpeer-ward-agent",
		CollectorVersion: Version,
		CollectedAt:      time.Now().UTC(),
		Host:             inventory.Host{UIDClass: uidClass(), OS: runtime.GOOS},
		Coverage:         []inventory.Note{},
	}
	if err := h.operatingSystem(ctx, &snap); err != nil {
		return inventory.Snapshot{}, err
	}
	for _, section := range notChecked {
		snap.AddNote(inventory.NotChecked, section.source, section.detail)
	}
	return snap, nil
}

func (h Host) operatingSystem(ctx context.Context, snap *inventory.Snapshot) error {
	out, err := h.command(ctx, "uname", "-srm")
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		snap.AddNote(inventory.Unavailable, "uname", "kernel identity was not collected")
	} else if line, ok := oneLine(out, 256); ok {
		snap.Host.Uname = line
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			snap.Host.Architecture = fields[len(fields)-1]
		}
	} else {
		snap.AddNote(inventory.Unavailable, "uname", "kernel identity was not collected")
	}

	if err := h.readRelease(snap); err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		if err := h.readMacOS(ctx, snap); err != nil {
			return err
		}
	}
	return nil
}

func (h Host) readRelease(snap *inventory.Snapshot) error {
	paths := h.OSReleasePaths
	if len(paths) == 0 {
		paths = []string{"/etc/os-release", "/usr/lib/os-release"}
	}
	var last error
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(file, osReleaseLimit+1))
		file.Close()
		if err != nil {
			last = err
			continue
		}
		if len(body) > osReleaseLimit {
			snap.AddNote(inventory.Truncated, "os-release", "os-release exceeds 1 MiB")
			return nil
		}
		snap.Host.Release = parseRelease(string(body), releaseKeys)
		if codename := inventory.UbuntuCodename(snap.Host.Release); codename != "" {
			snap.Host.Release["VERSION_CODENAME"] = codename
		}
		return nil
	}
	if last != nil {
		snap.AddNote(inventory.Unavailable, "os-release", "os-release was not readable")
	}
	return nil
}

func (h Host) readMacOS(ctx context.Context, snap *inventory.Snapshot) error {
	out, err := h.command(ctx, "sw_vers")
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		snap.AddNote(inventory.Unavailable, "sw_vers", "macOS version was not collected")
		return nil
	}
	parsed := parseRelease(string(out), macKeys)
	if len(parsed) == 0 {
		snap.AddNote(inventory.Unavailable, "sw_vers", "macOS version was not collected")
		return nil
	}
	if snap.Host.Release == nil {
		snap.Host.Release = map[string]string{}
	}
	for key, value := range parsed {
		snap.Host.Release[key] = value
	}
	return nil
}

func (h Host) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	if h.Command != nil {
		return h.Command(ctx, name, args...)
	}
	return h.commandLimit(ctx, 65536, name, args...)
}

func (h Host) commandLimit(ctx context.Context, limit int, name string, args ...string) ([]byte, error) {
	if h.Command != nil {
		return h.Command(ctx, name, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = "/"
	cmd.Env = []string{"LC_ALL=C", "PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_INSTALL_FROM_API=1", "NPM_CONFIG_UPDATE_NOTIFIER=false", "NPM_CONFIG_AUDIT=false", "NPM_CONFIG_FUND=false", "NPM_CONFIG_OFFLINE=true", "NPM_CONFIG_IGNORE_SCRIPTS=true"}
	out := limitedOutput{limit: limit}
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return out.data, err
}

func parseRelease(text string, allow map[string]struct{}) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			key, value, ok = strings.Cut(line, ":")
		}
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, wanted := allow[key]; !wanted {
			continue
		}
		cleaned, ok := cleanValue(value)
		if !ok {
			continue
		}
		out[key] = cleaned
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cleanValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		unquoted, err := strconv.Unquote(value)
		if err == nil {
			value = unquoted
		}
	}
	if value == "" || len(value) > 512 {
		return "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return value, true
}

func oneLine(raw []byte, limit int) (string, bool) {
	line := strings.TrimSpace(string(raw))
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" || len(line) > limit {
		return "", false
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return line, true
}

func uidClass() string {
	if os.Geteuid() == 0 {
		return "root"
	}
	return "unprivileged"
}

type limitedOutput struct {
	data  []byte
	limit int
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, io.ErrShortWrite
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
