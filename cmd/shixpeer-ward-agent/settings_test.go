package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shixpeer.com/ward/internal/beacon/catalog"
	"shixpeer.com/ward/internal/beacon/exporter"
	"shixpeer.com/ward/internal/beacon/publish"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/snapshot"
)

func TestSetupUpdateWithoutKeyFile(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	state := filepath.Join(dir, "state")
	public := filepath.Join(dir, "public")
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	builder, err := compactdb.NewBuilder(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	if err = builder.Put("r", "CVE-TEST", []byte(`{"id":"CVE-TEST"}`)); err != nil {
		t.Fatal(err)
	}
	buckets, err := builder.Finish(context.Background(), filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	summary := catalog.Summary{Format: compactdb.Format, Profile: compactdb.All, Generation: snapshot.Digest([]byte("fixture")), Buckets: buckets, Sources: []catalog.SourceStatus{{ID: "fixture", Advisories: 1, CheckedAt: time.Now()}}}
	if _, err = exporter.Export(context.Background(), public, summary, key, "", time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(publish.Artifacts(public))
	defer server.Close()
	ca := filepath.Join(dir, "ca.crt")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	keypath := filepath.Join(dir, "feed.pub")
	der, _ := x509.MarshalPKIXPublicKey(pub)
	os.WriteFile(keypath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600)
	if err = run([]string{"setup", "-config", config, "-state", state, "-feed-url", server.URL + "/v1/manifest.json", "-trusted-key", keypath, "-ca-file", ca}); err != nil {
		t.Fatal(err)
	}
	os.Remove(keypath)
	for _, cmd := range []string{"update", "pull"} {
		if err = run([]string{cmd, "-config", config}); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := os.Stat(config)
	if info.Mode().Perm() != 0600 {
		t.Fatal("settings permissions", info.Mode())
	}
	before, _ := os.ReadFile(filepath.Join(state, "database", "current.json"))
	// A wrong saved key must not overwrite an existing trusted database.
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if err = saveSettings(config, state, server.URL+"/v1/manifest.json", wrong, ca, ""); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"update", "-config", config}); err == nil {
		t.Fatal("wrong key accepted")
	}
	after, _ := os.ReadFile(filepath.Join(state, "database", "current.json"))
	if string(before) != string(after) {
		t.Fatal("failed update changed database")
	}
}

func TestSetupRejectsMissingTrustAndHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		url string
		key ed25519.PublicKey
	}{
		{"https://example.org/manifest.json", nil},
		{"http://example.org/manifest.json", pub},
	} {
		if err := saveSettings(path, t.TempDir(), tc.url, tc.key, "", ""); err == nil {
			t.Fatal("unsafe setup accepted")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid settings saved")
	}
	if _, err := loadSettings(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":99}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSettings(path); err == nil {
		t.Fatal("invalid settings accepted")
	}
}
