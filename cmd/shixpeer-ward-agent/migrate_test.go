package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/paths"
	"testing"
)

func TestMigrationPreservesTrustCheckpointAndOriginal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(t.TempDir(), "state")
	os.MkdirAll(filepath.Join(legacy, "database"), 0700)
	pointer := []byte(`{"envelope":"signed-checkpoint-opaque","key":"pinned"}`)
	os.WriteFile(filepath.Join(legacy, "database", "current.json"), pointer, 0600)
	os.WriteFile(filepath.Join(legacy, "report.md"), []byte("private fixture"), 0600)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(ca, []byte("fixture-ca"), 0600)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	config := filepath.Join(t.TempDir(), "agent.json")
	if err := atomicfile.JSON(config, settings{Version: 1, State: legacy, URL: "https://example.org/v1/manifest.json", Key: pub, CA: ca}); err != nil {
		t.Fatal(err)
	}
	if err := migrateHome([]string{"-from-config", config}); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(filepath.Join(paths.State("agent"), "database", "current.json"))
	if err != nil || !bytes.Equal(copied, pointer) {
		t.Fatal("checkpoint changed", err)
	}
	s, err := loadSettings(paths.Config("agent"))
	if err != nil || s.State != paths.State("agent") || !bytes.Equal(pub, s.Key) || s.CA == ca {
		t.Fatal(s, err)
	}
	if _, err = os.Stat(filepath.Join(legacy, "report.md")); err != nil {
		t.Fatal("original removed")
	}
	if err = migrateHome([]string{"-from-config", config}); err == nil {
		t.Fatal("existing trust overwritten")
	}
}
func TestMigrationRejectsSymlinks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	legacy := t.TempDir()
	os.Symlink("/etc/passwd", filepath.Join(legacy, "unsafe"))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	config := filepath.Join(t.TempDir(), "agent.json")
	atomicfile.JSON(config, settings{Version: 1, State: legacy, URL: "https://example.org/feed", Key: pub})
	if err := migrateHome([]string{"-from-config", config}); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := os.Stat(paths.Config("agent")); !os.IsNotExist(err) {
		t.Fatal("failed migration committed settings")
	}
}
