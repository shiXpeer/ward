package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"shixpeer.com/ward/pkg/inventory"
)

func TestHostSnapshotKeepsReleaseIdentityOnly(t *testing.T) {
	dir := t.TempDir()
	release := filepath.Join(dir, "os-release")
	body := []byte(strings.Join([]string{
		`ID=ubuntu`,
		`VERSION_ID="24.04"`,
		`PRETTY_NAME="Ubuntu 24.04.1 LTS"`,
		`HOME=/secret/home`,
		`HOSTNAME=hidden.example`,
		``,
	}, "\n"))
	if err := os.WriteFile(release, body, 0o600); err != nil {
		t.Fatal(err)
	}
	var commands []string
	host := Host{
		OSReleasePaths: []string{release},
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			command := name
			if len(args) > 0 {
				command += " " + strings.Join(args, " ")
			}
			commands = append(commands, command)
			switch name {
			case "uname":
				return []byte("Linux 6.8.0-45-generic x86_64\n"), nil
			case "sw_vers":
				return []byte("ProductName:\tmacOS\nProductVersion:\t15.1\nBuildVersion:\t24B83\n"), nil
			default:
				t.Fatalf("unexpected command %s", name)
				return nil, nil
			}
		},
	}
	snap, err := host.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	if snap.Host.Uname != "Linux 6.8.0-45-generic x86_64" || snap.Host.Architecture != "x86_64" {
		t.Fatalf("host identity %#v", snap.Host)
	}
	if snap.Host.Release["ID"] != "ubuntu" || snap.Host.Release["VERSION_ID"] != "24.04" {
		t.Fatalf("release %#v", snap.Host.Release)
	}
	if snap.Host.UIDClass != "root" && snap.Host.UIDClass != "unprivileged" {
		t.Fatal(snap.Host.UIDClass)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"/secret/home", "hidden.example", "hostname"} {
		if strings.Contains(text, secret) {
			t.Fatalf("snapshot contains %s", secret)
		}
	}
	want := []string{"uname -srm"}
	if runtime.GOOS == "darwin" {
		want = append(want, "sw_vers")
		if snap.Host.Release["ProductVersion"] != "15.1" {
			t.Fatalf("macOS release %#v", snap.Host.Release)
		}
	}
	if strings.Join(commands, ",") != strings.Join(want, ",") {
		t.Fatalf("commands %q", commands)
	}
	seen := map[string]bool{}
	for _, note := range snap.Coverage {
		if note.Code == inventory.NotChecked {
			seen[note.Source] = true
		}
	}
	for _, section := range []string{"packages", "services", "listeners", "applications", "containers", "dependencies"} {
		if !seen[section] {
			t.Fatalf("missing not-checked note for %s in %#v", section, snap.Coverage)
		}
	}
}

func TestHostSnapshotRecordsMissingRelease(t *testing.T) {
	host := Host{
		OSReleasePaths: []string{filepath.Join(t.TempDir(), "missing")},
		Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "sw_vers" {
				return []byte("nope\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	snap, err := host.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, note := range snap.Coverage {
		codes[note.Source] = note.Code
	}
	if codes["uname"] != inventory.Unavailable || codes["os-release"] != inventory.Unavailable {
		t.Fatalf("coverage %#v", snap.Coverage)
	}
}
