package main

import (
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/identity"
	"strings"
	"testing"
	"time"
)

func TestPublicationPreservesManifestWhenSourceFailed(t *testing.T) {
	dir := t.TempDir()
	pki := filepath.Join(dir, "pki")
	if e := identity.Init(pki, []string{"localhost"}, time.Now()); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(dir, "state")
	public := filepath.Join(dir, "public")
	fixture, e := filepath.Abs("../../configs/beacon.demo.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"sync", "-state", state, "-sources", fixture}); e != nil {
		t.Fatal(e)
	}
	args := []string{"export", "-state", state, "-out", public, "-signing-key", filepath.Join(pki, "signing.key")}
	if e = run(args); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(public, "manifest.json"))
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{"sources":[{"id":"failed","type":"osv","path":"missing.json","enabled":true}]}`), 0600)
	if e = run([]string{"sync", "-state", state, "-sources", broken}); e == nil {
		t.Fatal("failed source accepted")
	}
	if e = run(args); e == nil || !strings.Contains(e.Error(), "refusing to publish") {
		t.Fatal("published partial coverage", e)
	}
	after, _ := os.ReadFile(filepath.Join(public, "manifest.json"))
	if string(before) != string(after) {
		t.Fatal("manifest replaced")
	}
}
