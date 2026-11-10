package collect

import (
	"context"
	"os"
	"path/filepath"
	"shixpeer.com/ward/pkg/inventory"
	"strings"
	"testing"
)

func TestSocketParsersFamiliesAndVisibility(t *testing.T) {
	s := inventory.Snapshot{}
	text := "p42\ncweb\nf3\ntIPv6\nPTCP\nn[::]:8200\nf4\ntIPv4\nPUDP\nn127.0.0.1:5353\nf5\nPUDP\nn127.0.0.1:4000->127.0.0.1:4001\n"
	if e := parseLSOF(text, &s); e != nil || len(s.Listeners) != 2 {
		t.Fatal(s, e)
	}
	if s.Listeners[0].BindScope != "wildcard" || s.Listeners[1].BindScope != "loopback" || s.Listeners[0].Process != "web" || s.Listeners[0].PID != 42 {
		t.Fatal(s)
	}
	if e := parseSS("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=9,fd=3))\nudp UNCONN 0 0 [::1]:53 [::]:*\n", &s); e != nil {
		t.Fatal(e)
	}
	if s.Listeners[2].Process != "sshd" || s.Listeners[3].Family != "IPv6" || s.Listeners[3].BindScope != "loopback" {
		t.Fatal(s.Listeners)
	}
	// Public examples stay in RFC 5737 documentation ranges.
	for host, want := range map[string]string{"0.0.0.0": "wildcard", "::": "wildcard", "127.0.0.1": "loopback", "::1": "loopback", "172.19.0.1": "private", "198.51.100.171": "public-address"} {
		if got := bindScope(host); got != want {
			t.Fatal(host, got)
		}
	}
}
func TestServiceAndDockerMetadata(t *testing.T) {
	s := inventory.Snapshot{}
	parseLaunchctl("PID Status Label\n42 0 local.example\n- 0 local.loaded\n", &s)
	parseSystemctl("sshd.service loaded active running SSH server\n", &s)
	if len(s.Services) != 3 || s.Services[0].Active != "running" || s.Services[1].Active != "loaded" {
		t.Fatal(s.Services)
	}
	row := `{"name":"/node-exporter","image":"exporter:1","image_id":"sha256:test","started_at":"2026-01-01","ports":{"9100/tcp":[{"HostIP":"0.0.0.0","HostPort":"9100"},{"HostIP":"::1","HostPort":"9100"}]}}`
	if e := parseDocker(row, &s); e != nil || len(s.Containers) != 1 || len(s.Containers[0].Ports) != 2 {
		t.Fatal(s, e)
	}
	if s.Containers[0].Ports[1].Reachability != "UNKNOWN" {
		t.Fatal(s)
	}
}
func TestDockerExplicitUnixEndpointAndNoSecrets(t *testing.T) {
	id := strings.Repeat("a", 64)
	calls := 0
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if name != "docker" || len(args) < 4 || args[0] != "--host" || args[1] != "unix:///fixture.sock" {
			t.Fatal(name, args)
		}
		if args[3] == "ls" {
			return []byte(id + "\n"), nil
		}
		if args[3] != "inspect" || strings.Contains(args[5], ".Config.Env") || !strings.Contains(args[5], ".Config.Image") {
			t.Fatal(args)
		}
		return []byte(`{"name":"/fixture","image":"local","ports":{}}`), nil
	}}
	s := inventory.Snapshot{}
	h.docker(context.Background(), &s, "/fixture.sock")
	if calls != 2 || len(s.Containers) != 1 {
		t.Fatal(s, calls)
	}
}
func TestCoreReceiptDoesNotTrustForkOrHead(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "curl", "8.0_1")
	os.MkdirAll(path, 0700)
	for _, tc := range []struct{ tap, spec, want string }{{"homebrew/core", "stable", "8.0"}, {"custom/tap", "stable", ""}, {"homebrew/core", "head", ""}} {
		raw := `{"source":{"tap":"` + tc.tap + `","spec":"` + tc.spec + `","versions":{"stable":"8.0"}}}`
		os.WriteFile(filepath.Join(path, "INSTALL_RECEIPT.json"), []byte(raw), 0600)
		_, version, _ := brewReceipt(root, "curl", "8.0_1")
		if version != tc.want {
			t.Fatal(tc, version)
		}
	}
	if _, version, _ := brewReceipt(root, "../../secret", "x"); version != "" {
		t.Fatal("path traversal accepted")
	}
}

func TestLanguageInventoryUsesIsolatedOfflineProbes(t *testing.T) {
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name == "python3" {
			if !strings.HasPrefix(joined, "-I -S -c ") {
				t.Fatal(args)
			}
			return []byte(`[{"name":"Example_Package.Name","version":"1.2.3"}]`), nil
		}
		if name == "npm" {
			for _, flag := range []string{"--offline", "--ignore-scripts", "--no-audit", "--global"} {
				if !strings.Contains(joined, flag) {
					t.Fatal(args)
				}
			}
			return []byte(`{"dependencies":{"@scope/example":{"version":"1.0.0"}}}`), nil
		}
		t.Fatal(name, args)
		return nil, nil
	}}
	s := inventory.Snapshot{}
	h.globalDependencies(context.Background(), &s)
	if len(s.Dependencies) != 2 || s.Dependencies[0].Name != "example-package-name" {
		t.Fatal(s)
	}
}

func TestProcSocketFallbackWithoutSS(t *testing.T) {
	s := inventory.Snapshot{}
	rows := " sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 123\n 1: 00000000:0051 00000000:0000 01 0 0 0 1000 0 124\n"
	if err := parseProcNet(rows, "tcp", &s); err != nil {
		t.Fatal(err)
	}
	six := "0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 0 0 0 1000 0 125\n"
	if err := parseProcNet(six, "udp6", &s); err != nil {
		t.Fatal(err)
	}
	if len(s.Listeners) != 2 || s.Listeners[0].Port != 80 || s.Listeners[0].BindScope != "loopback" || s.Listeners[1].Family != "IPv6" || s.Listeners[1].BindScope != "loopback" {
		t.Fatal(s.Listeners)
	}
}
