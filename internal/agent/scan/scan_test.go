package scan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/snapshot"
	"shixpeer.com/ward/pkg/inventory"
	"shixpeer.com/ward/pkg/vuln"
)

func fixture(t *testing.T, expired bool) (string, ed25519.PublicKey) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	b, err := compactdb.NewBuilder(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	put := func(group, key string, v any) {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = b.Put(group, key, raw); e != nil {
			t.Fatal(e)
		}
	}
	put("p", compactdb.PackageKey("Debian:bookworm", "openssl"), compactdb.Row{Source: "vendor", ID: "TEST-1", Ecosystem: "Debian:bookworm", Package: "openssl", Ranges: []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "1:3.0.14-1~deb12u2"}}}}})
	put("v", "TEST-1", compactdb.Row{Source: "vendor", ID: "TEST-1", Aliases: []string{"CVE-SYNTHETIC-1"}, Severity: "HIGH", References: []string{"https://example.org/advisory"}})
	put("r", "CVE-SYNTHETIC-1", compactdb.Row{Source: "kev", ID: "CVE-SYNTHETIC-1", KnownExploited: true})
	put("p", compactdb.PackageKey("macOS", "macOS"), compactdb.Row{Source: "sofa", ID: "TEST-MAC", Ecosystem: "macOS", Package: "macOS", Context: json.RawMessage(`{"fixed_version":"15.3","applicability":"vendor-bulletin-review-required"}`)})
	put("p", compactdb.PackageKey("CPE", "a:haxx:curl"), compactdb.Row{Source: "fixture-nvd", ID: "CVE-CURL-FIXTURE", Ecosystem: "CPE", Package: "a:haxx:curl", Context: json.RawMessage(`{"cpe":{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.0.1"},"complex":false}}`)})
	put("p", compactdb.PackageKey("CPE", "a:haxx:curl"), compactdb.Row{Source: "fixture-nvd", ID: "CVE-CURL-FIXTURE", Ecosystem: "CPE", Package: "a:haxx:curl", Review: true, Context: json.RawMessage(`{"cpe":{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.0.1"},"complex":true}}`)})
	put("v", "CVE-CURL-FIXTURE", compactdb.Row{Source: "fixture-nvd", ID: "CVE-CURL-FIXTURE", Severity: "HIGH"})
	bs, e := b.Finish(ctx, filepath.Join(dir, "compiled"))
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	if expired {
		now = now.Add(-2 * time.Hour)
	}
	m := snapshot.Manifest{Version: snapshot.Version, Format: compactdb.Format, Revision: now.UnixNano(), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Profile: compactdb.All, Generation: snapshot.Digest([]byte("test")), Sources: []compactdb.SourceStatus{{ID: "fixture", CheckedAt: now, RuleFormats: []string{"nvd-cpe-v1"}}}}
	for _, bucket := range bs {
		raw, e := os.ReadFile(bucket.Path)
		if e != nil {
			t.Fatal(e)
		}
		sha := compactdb.Digest(raw)
		if e = atomicfile.Write(filepath.Join(dir, "objects", sha+".wdb"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		m.Objects = append(m.Objects, snapshot.Object{Slot: bucket.Slot, SHA256: sha, Bytes: int64(len(raw)), Rows: bucket.Rows})
	}
	env, e := snapshot.Sign(m, key)
	if e != nil {
		t.Fatal(e)
	}
	p := struct {
		Envelope []byte `json:"envelope"`
		Key      []byte `json:"key"`
	}{env, pub}
	if e = atomicfile.JSON(filepath.Join(dir, "current.json"), p); e != nil {
		t.Fatal(e)
	}
	return dir, pub
}
func TestOfflineReportSourceVersionRiskAndMacReview(t *testing.T) {
	dir, key := fixture(t, false)
	db, e := database.OpenReader(context.Background(), dir, key)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := inventory.Snapshot{FormatVersion: 1, CollectedAt: time.Now(), Collector: "fixture", Coverage: []inventory.Note{}, Host: inventory.Host{Release: map[string]string{"ID": "debian", "VERSION_CODENAME": "bookworm", "ProductVersion": "15.2"}}, Packages: []inventory.Package{
		{Manager: "dpkg", Name: "libssl3", Version: "1.0-binary", SourceName: "openssl", SourceVersion: "1:3.0.14-1~deb12u1"},
		{Manager: "dpkg", Name: "openssl", Version: "1:3.0.14-1~deb12u1", SourceName: "openssl", SourceVersion: "1:3.0.14-1~deb12u1"},
		{Manager: "homebrew-formula", Name: "openssl", Version: "1.0"},
	}}
	r := New(s)
	if e = Run(context.Background(), &r, db); e != nil {
		t.Fatal(e)
	}
	if r.Confirmed != 1 || r.Review != 1 || len(r.Components) != 3 {
		t.Fatalf("%+v", r)
	}
	f := r.Findings[0]
	if f.Priority != "P0-known-exploited" || f.Severity != "HIGH" || len(f.Fixed) != 1 || f.Fixed[0] != "1:3.0.14-1~deb12u2" {
		t.Fatal(f)
	}
	if r.Findings[1].Status != "review" {
		t.Fatal(r.Findings)
	}
	if r.Components[2].Result != "NOT_CHECKED" {
		t.Fatal("brew misidentified", r.Components)
	}
	out := t.TempDir()
	if e = Save(out, r); e != nil {
		t.Fatal(e)
	}
	var decoded Report
	if e = atomicfile.ReadJSON(filepath.Join(out, "report.json"), &decoded, 16<<20); e != nil {
		t.Fatal(e)
	}
	if decoded.Confirmed != 1 || !decoded.Offline || decoded.FormatVersion != 1 {
		t.Fatal(decoded)
	}
	md, e := os.ReadFile(filepath.Join(out, "report.md"))
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"P0-known-exploited", "does not mean this system is safe", "NOT_CHECKED", "TEST-MAC"} {
		if !strings.Contains(string(md), want) {
			t.Fatal("missing report content", want)
		}
	}
	info, _ := os.Stat(filepath.Join(out, "report.md"))
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
func TestScanRejectsExpiredDatabaseAndWrongTrust(t *testing.T) {
	expired, key := fixture(t, true)
	if db, e := database.OpenReader(context.Background(), expired, key); e == nil {
		db.Close()
		t.Fatal("expired database accepted")
	}
	dir, _ := fixture(t, false)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	if db, e := database.OpenReader(context.Background(), dir, wrong); e == nil {
		db.Close()
		t.Fatal("wrong signing key accepted")
	}
}
func TestMarkdownEscapesInventory(t *testing.T) {
	r := New(inventory.Snapshot{Applications: []inventory.Application{{Name: "<script>|bad\nrow", Version: "1.0"}}})
	text := Markdown(r)
	if strings.Contains(text, "<script>") || strings.Contains(text, "bad\nrow") {
		t.Fatal("unescaped inventory")
	}
}

func TestMissingCPERuleCapabilityIsExplicitlyUnchecked(t *testing.T) {
	dir, key := fixture(t, false)
	db, e := database.OpenReader(context.Background(), dir, key)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	db.Manifest.Sources[0].RuleFormats = nil
	s := inventory.Snapshot{Packages: []inventory.Package{{Manager: "homebrew-formula", Name: "curl", Version: "8.0_1", Provenance: "homebrew/core", UpstreamVersion: "8.0"}}}
	r := New(s)
	if e = Run(context.Background(), &r, db); e != nil {
		t.Fatal(e)
	}
	if len(r.Components) != 1 || r.Components[0].Result != "NOT_CHECKED" || !strings.Contains(r.Components[0].Reason, "predates") {
		t.Fatal(r.Components)
	}
}

func TestOfflineCoreCPEProofAndDuplicateRuleAggregation(t *testing.T) {
	dir, key := fixture(t, false)
	db, e := database.OpenReader(context.Background(), dir, key)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := inventory.Snapshot{Host: inventory.Host{Release: map[string]string{"ProductVersion": "26.5"}, Architecture: "arm64"}, Packages: []inventory.Package{{Manager: "homebrew-formula", Name: "curl", Version: "8.0_1", Provenance: "homebrew/core", UpstreamVersion: "8.0"}}}
	r := New(s)
	if e = Run(context.Background(), &r, db); e != nil {
		t.Fatal(e)
	}
	if r.Confirmed != 1 || r.Review != 0 || len(r.Findings) != 1 || r.Findings[0].RuleMatches != 2 || r.Findings[0].MatchVersion != "8.0" || r.Findings[0].Evidence.Review {
		t.Fatalf("%+v", r)
	}
}
