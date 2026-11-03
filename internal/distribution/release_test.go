package distribution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureBinaries(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		b := make([]byte, 128)
		copy(b, []byte("\x7fELF"))
		b[4] = 2
		b[5] = 1
		b[18] = 62
		if arch == "arm64" {
			b[18] = 183
		}
		if err := os.WriteFile(filepath.Join(dir, "shixpeer-ward-agent-linux-"+arch), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
func TestSignedReleaseAndAllowlist(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	out := t.TempDir()
	pin, err := Release(out, fixtureBinaries(t), "0.4.0-test", key, time.Now(), time.Hour)
	if err != nil || len(pin) != 64 {
		t.Fatal(pin, err)
	}
	raw, _ := os.ReadFile(filepath.Join(out, "agents.txt"))
	sig, _ := os.ReadFile(filepath.Join(out, "agents.sig"))
	if !ed25519.Verify(pub, raw, sig) {
		t.Fatal("invalid release signature")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 6 || lines[0] != "WARD-AGENT-RELEASE-V1" {
		t.Fatal(lines)
	}
	for _, line := range lines[4:] {
		f := strings.Split(line, "\t")
		if len(f) != 3 || !Allowed(f[2]) {
			t.Fatal(f)
		}
		data, err := os.ReadFile(filepath.Join(out, f[2]))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != f[0] || strconv.Itoa(len(data)) != f[1] {
			t.Fatal("artifact not bound to manifest")
		}
	}
	script, _ := os.ReadFile(filepath.Join(out, "install.sh"))
	hash := sha256.Sum256(script)
	if InstallerDigest() != hex.EncodeToString(hash[:]) {
		t.Fatal("installer bootstrap pin mismatch")
	}
	raw[0] ^= 1
	if ed25519.Verify(pub, raw, sig) {
		t.Fatal("tampered manifest verified")
	}
	for _, path := range []string{"signing.key", "server.key", "../feed.pub", "ca.key", "snapshot.json", "agent-linux-amd64-unknown"} {
		if Allowed(path) {
			t.Fatal("unsafe public path", path)
		}
	}
}
func TestReleaseRejectsWrongArchitectureAndValidity(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := fixtureBinaries(t)
	os.WriteFile(filepath.Join(dir, "shixpeer-ward-agent-linux-arm64"), []byte("not a Linux binary"), 0600)
	if _, err := Release(t.TempDir(), dir, "test", key, time.Now(), time.Hour); err == nil {
		t.Fatal("wrong executable accepted")
	}
	if _, err := Release(t.TempDir(), fixtureBinaries(t), "test", key, time.Now(), 31*24*time.Hour); err == nil {
		t.Fatal("unbounded release expiry")
	}
}
