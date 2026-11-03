package source

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testOSV = `{"schema_version":"1.6.0","id":"OSV-TEST-1","aliases":["CVE-2026-1234"],"modified":"2026-10-30T00:00:00Z","published":"2026-10-30T00:00:00Z","affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-0ubuntu3.5"}]}]}],"database_specific":{"severity":"CRITICAL"}}`

func TestLocalOSVAndRangePreservation(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "record.json"), []byte(testOSV), 0600)
	os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"sources":[{"id":"test","type":"osv","path":"record.json","enabled":true}]}`), 0600)
	s, e := Load(filepath.Join(dir, "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := s[0].Sync(context.Background(), "")
	if e != nil || !b.Full || len(b.Advisories) != 1 {
		t.Fatal(b, e)
	}
	a := b.Advisories[0]
	if len(a.Affected[0].Ranges[0].Events) != 2 || len(a.Raw) == 0 {
		t.Fatal("OSV semantics lost")
	}
}
func TestOSVArchive(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, _ := z.Create("../../no-extraction.json")
	f.Write([]byte(testOSV))
	z.Close()
	rows, e := parseOSVZip(context.Background(), b.Bytes())
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
}
func TestKEVAndInvalidInputs(t *testing.T) {
	rows, e := parseKEV([]byte(`{"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-10-30","vulnerabilityName":"Test"}]}`))
	if e != nil || !rows[0].KnownExploited || rows[0].ExploitedAt.IsZero() {
		t.Fatal(rows, e)
	}
	for _, raw := range []string{`{}`, `{"id":"x"}`, `[{"id":"x","modified":"2026-10-30T00:00:00Z"},{"id":"x","modified":"2026-10-30T00:00:00Z"}]`} {
		if _, e = parseOSVDocument([]byte(raw)); e == nil {
			t.Fatal("accepted malformed/duplicate", raw)
		}
	}
	_ = json.Valid
	_ = time.Second
}
func TestConfigurationRejectsUnknownAdapterAndPlainHTTP(t *testing.T) {
	for _, body := range []string{`{"sources":[{"id":"x","type":"shell","path":"x","enabled":true}]}`, `{"sources":[{"id":"x","type":"osv","url":"http://example.org/feed","enabled":true}]}`, `{"sources":[{"id":"x","type":"osv","url":"https://user:pass@example.org/feed","enabled":true}]}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		os.WriteFile(path, []byte(body), 0600)
		if _, e := Load(path); e == nil {
			t.Fatal("accepted unsafe config")
		}
	}
}
