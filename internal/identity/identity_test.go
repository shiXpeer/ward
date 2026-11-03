package identity

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityAndSeparateSigningKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	if e := Init(dir, []string{"localhost", "127.0.0.1"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := Init(dir, []string{"localhost"}, time.Now()); e == nil {
		t.Fatal("overwrote keys")
	}
	sign, e := Private(filepath.Join(dir, "signing.key"))
	if e != nil {
		t.Fatal(e)
	}
	server, e := Private(filepath.Join(dir, "server.key"))
	if e != nil {
		t.Fatal(e)
	}
	if string(sign) == string(server) {
		t.Fatal("reused TLS signing key")
	}
	pair, e := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	ca, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots.AppendCertsFromPEM(ca)
	if _, e = leaf.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: roots}); e != nil {
		t.Fatal(e)
	}
	os.Chmod(filepath.Join(dir, "signing.key"), 0644)
	if _, e = Private(filepath.Join(dir, "signing.key")); e == nil {
		t.Fatal("accepted public private key")
	}
}
