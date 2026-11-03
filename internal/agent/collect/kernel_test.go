package collect

import (
	"context"
	"shixpeer.com/ward/pkg/inventory"
	"testing"
)

func TestUbuntuRunningVersionNotInstalledVersion(t *testing.T) {
	for _, tc := range []struct{ release, sig, want string }{
		{"6.8.0-45-generic", "Ubuntu 6.8.0-45.45-generic 6.8.12", "6.8.0-45.45"},
		{"5.15.0-67-generic", "Ubuntu 5.15.0-67.74~20.04.1-generic 5.15.85", "5.15.0-67.74~20.04.1"},
		{"6.8.0-45-generic", "Ubuntu 6.8.0-46.46-generic 6.8.12", ""},
		{"custom", "unverifiable", ""},
	} {
		if got := ubuntuKernelVersion(tc.release, tc.sig); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestDebianLoadedKernelTriggersRebootWarning(t *testing.T) {
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("#1 SMP Debian 6.1.106-3 (2024-08-26)"), nil
	}}
	s := inventory.Snapshot{Host: inventory.Host{Uname: "Linux 6.1.0-25-amd64 x86_64", Release: map[string]string{"ID": "debian"}}, Packages: []inventory.Package{{Name: "linux-image-6.1.0-25-amd64", SourceName: "linux", SourceVersion: "6.1.106-4"}}}
	h.runningKernel(context.Background(), &s)
	if s.RunningKernel == nil || s.RunningKernel.SourceVersion != "6.1.106-3" || !s.RunningKernel.RebootRequired {
		t.Fatal(s.RunningKernel)
	}
}

func TestDebianVersionSignatureDoesNotDropSuffix(t *testing.T) {
	m := debianBuild.FindStringSubmatch("#1 SMP Debian 6.1.106-3+ (2024-08-26)")
	if len(m) != 2 || m[1] != "6.1.106-3+" {
		t.Fatal(m)
	}
}
