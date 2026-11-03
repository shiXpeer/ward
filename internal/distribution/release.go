// Package distribution publishes signed Linux agent installation artifacts.
package distribution

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
)

//go:embed install-agent.sh
var installer embed.FS
var Binary = regexp.MustCompile(`^agent-linux-(amd64|arm64)-[a-f0-9]{64}$`)

func Allowed(name string) bool {
	return name == "install.sh" || name == "agents.txt" || name == "agents.sig" || name == "feed.pub" || Binary.MatchString(name)
}

// Release signs a bounded, canonical TSV manifest and content-addressed binaries.
// Only a public key is published. No server/signing private keys are served.
func Release(out, binaries, version string, key ed25519.PrivateKey, now time.Time, ttl time.Duration) (string, error) {
	if len(key) != ed25519.PrivateKeySize || ttl < time.Hour || ttl > 30*24*time.Hour {
		return "", errors.New("valid signing key and release TTL 1h..30d required")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`).MatchString(version) {
		return "", errors.New("invalid release version")
	}
	body := fmt.Sprintf("WARD-AGENT-RELEASE-V1\n%d\n%d\n%s\n", now.Unix(), now.Add(ttl).Unix(), version)
	for _, arch := range []string{"amd64", "arm64"} {
		src := filepath.Join(binaries, "shixpeer-ward-agent-linux-"+arch)
		f, err := os.Open(src)
		if err != nil {
			return "", err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return "", err
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
			f.Close()
			return "", errors.New("invalid agent binary size/type")
		}
		head := make([]byte, 20)
		_, err = io.ReadFull(f, head)
		if err != nil {
			f.Close()
			return "", err
		}
		machine := uint16(head[18]) | uint16(head[19])<<8
		want := uint16(62)
		if arch == "arm64" {
			want = 183
		}
		if string(head[:4]) != "\x7fELF" || head[4] != 2 || head[5] != 1 || machine != want {
			f.Close()
			return "", fmt.Errorf("%s is not a little-endian Linux ELF for %s", src, arch)
		}
		if _, err = f.Seek(0, 0); err != nil {
			f.Close()
			return "", err
		}
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			f.Close()
			return "", err
		}
		digest := hex.EncodeToString(h.Sum(nil))
		if _, err = f.Seek(0, 0); err != nil {
			f.Close()
			return "", err
		}
		name := "agent-linux-" + arch + "-" + digest
		err = atomicfile.Stream(filepath.Join(out, name), func(w io.Writer) error { _, e := io.Copy(w, f); return e })
		f.Close()
		if err != nil {
			return "", err
		}
		if err = os.Chmod(filepath.Join(out, name), 0644); err != nil {
			return "", err
		}
		body += fmt.Sprintf("%s\t%d\t%s\n", digest, info.Size(), name)
	}
	pub := key.Public().(ed25519.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	script, err := installer.ReadFile("install-agent.sh")
	if err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{"agents.sig": ed25519.Sign(key, []byte(body)), "feed.pub": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "install.sh": script} {
		if err = atomicfile.Write(filepath.Join(out, name), data, 0644); err != nil {
			return "", err
		}
	}
	// Manifest last. A concurrent release race may transiently fail closed; retries
	// are safe, and content-addressed binaries never change under a signed name.
	if err = atomicfile.Write(filepath.Join(out, "agents.txt"), []byte(body), 0644); err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// InstallerDigest is an out-of-band bootstrap pin: trusting TLS alone would let
// a compromised HTTPS worker replace a root-executed installer before key checks.
func InstallerDigest() string {
	raw, _ := installer.ReadFile("install-agent.sh")
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
