package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/reportrelay"
)

func TestEnableEnrollmentPreservesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.json")
	cfg := reportrelay.Config{Reader: strings.Repeat("r", 32), Writers: map[string]string{"legacy": strings.Repeat("w", 32)}}
	data, _ := json.Marshal(cfg)
	if e := atomicfile.Write(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if e := configureEnrollment("enable-enrollment", []string{"-config", path}); e != nil {
		t.Fatal(e)
	}
	var first reportrelay.Config
	_ = atomicfile.ReadJSON(path, &first, 1<<20)
	if len(first.Enrollment) != 64 || first.Reader != cfg.Reader || first.Writers["legacy"] != cfg.Writers["legacy"] {
		t.Fatal("credentials changed")
	}
	if e := configureEnrollment("enable-enrollment", []string{"-config", path}); e != nil {
		t.Fatal(e)
	}
	var second reportrelay.Config
	_ = atomicfile.ReadJSON(path, &second, 1<<20)
	if first.Enrollment != second.Enrollment {
		t.Fatal("management token silently rotated")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config permissions")
	}
}
