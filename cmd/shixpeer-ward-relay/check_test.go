package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/reportrelay"
)

func captureCheck(t *testing.T, args []string) (string, error) {
	t.Helper()
	previous := os.Stdout
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	os.Stdout = write
	defer func() { os.Stdout = previous; read.Close() }()
	err := checkRelay(args)
	write.Close()
	raw, _ := io.ReadAll(read)
	return string(raw), err
}
func TestReadinessChecksTLSAndAuthBeforeCredentials(t *testing.T) {
	root := t.TempDir()
	cfg := reportrelay.Config{Reader: strings.Repeat("r", 32), Enrollment: strings.Repeat("e", 32)}
	handler, e := cfg.Handler(filepath.Join(root, "reports"))
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	cert := filepath.Join(root, "ca.crt")
	if e := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, "relay.json")
	raw, _ := json.Marshal(cfg)
	if e := atomicfile.Write(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	args := []string{"-config", path, "-url", server.URL, "-ca-file", cert}
	output, err := captureCheck(t, args)
	if err != nil || !strings.Contains(output, "Relay ready:") || !strings.Contains(output, cfg.Reader) || !strings.Contains(output, cfg.Enrollment) {
		t.Fatal("readiness failed", err)
	}
	output, err = captureCheck(t, args[:4])
	if err == nil || output != "" {
		t.Fatal("untrusted TLS exposed credentials")
	}
	cfg.Reader = strings.Repeat("x", 32)
	raw, _ = json.Marshal(cfg)
	_ = atomicfile.Write(path, raw, 0600)
	output, err = captureCheck(t, args)
	if err == nil || output != "" {
		t.Fatal("failed authentication exposed credentials")
	}
	output, err = captureCheck(t, []string{"-config", path, "-url", "http://localhost"})
	if err == nil || output != "" {
		t.Fatal("HTTP readiness accepted")
	}
}
