package scan

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/productid"
	"shixpeer.com/ward/internal/snapshot"
	"shixpeer.com/ward/pkg/inventory"
	"shixpeer.com/ward/pkg/vuln"
)

func fixture(t *testing.T, expired bool, extra ...compactdb.Row) (string, ed25519.PublicKey) {
	t.Helper()
	return fixtureWithCoverage(t, expired, true, "nvd-cpe-v1", extra...)
}

func fixtureWithCoverage(t *testing.T, expired, includePolicy bool, format string, extra ...compactdb.Row) (string, ed25519.PublicKey) {
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
	for _, r := range extra {
		put("p", compactdb.PackageKey(r.Ecosystem, r.Package), r)
	}
	bs, e := b.Finish(ctx, filepath.Join(dir, "compiled"))
	if e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	if expired {
		now = now.Add(-2 * time.Hour)
	}
	m := snapshot.Manifest{ProductPolicy: &snapshot.ProductPolicy{Version: 1,
		Bundle:  map[string]string{"com.docker.docker": productid.Policy.Bundle["com.docker.docker"]},
		Formula: map[string]string{"curl": "a:haxx:curl", "fixture-new-formula": "a:haxx:curl"},
		Exclusions: []snapshot.ProductExclusion{{Product: "a:haxx:curl", CVEs: []string{"CVE-2026-12345"},
			Formula: "fixture-new-formula", Installed: "8.0_2", Upstream: "8.0"}}}, Version: snapshot.Version, Format: compactdb.Format, Revision: now.UnixNano(), CreatedAt: now, ExpiresAt: now.Add(time.Hour), Profile: compactdb.All, Generation: snapshot.Digest([]byte("test")), Sources: []compactdb.SourceStatus{{ID: "fixture", CheckedAt: now, RuleFormats: []string{format}}}}
	if !includePolicy {
		m.ProductPolicy = nil
	}
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
func TestMacOSCoverageRequiresMatchingBranch(t *testing.T) {
	dir, key := fixture(t, false)
	db, err := database.OpenReader(context.Background(), dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tc := range []struct{ version, result string }{
		{"27.3", "NOT_CHECKED"},
		{"15.3", "NO_MATCH_IN_AVAILABLE_RULES"},
		{"15.2", "REQUIRES_REVIEW"},
	} {
		t.Run(tc.version, func(t *testing.T) {
			r := New(inventory.Snapshot{Host: inventory.Host{Release: map[string]string{"ProductVersion": tc.version}}})
			if err := Run(context.Background(), &r, db); err != nil {
				t.Fatal(err)
			}
			if got := r.Components[0]; got.Result != tc.result {
				t.Fatalf("macOS %s: got %+v, want %s", tc.version, got, tc.result)
			}
		})
	}
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
	s := inventory.Snapshot{Host: inventory.Host{Release: map[string]string{"ProductVersion": "26.5"}, Architecture: "arm64"}, Packages: []inventory.Package{{Manager: "homebrew-formula", Name: "fixture-new-formula", Version: "8.0_1", Provenance: "homebrew/core", UpstreamVersion: "8.0"}}}
	r := New(s)
	if e = Run(context.Background(), &r, db); e != nil {
		t.Fatal(e)
	}
	if r.Confirmed != 1 || r.Review != 0 || len(r.Findings) != 1 || r.Findings[0].Component != "fixture-new-formula" || r.Findings[0].RuleMatches != 2 || r.Findings[0].MatchVersion != "8.0" || r.Findings[0].Evidence.Review {
		t.Fatalf("%+v", r)
	}
}

func TestKernelOutputFloodDoesNotPreventLaterPackageCheck(t *testing.T) {
	rows := make([]compactdb.Row, 10025)
	for i := range rows {
		rows[i] = compactdb.Row{Source: "fixture", ID: fmt.Sprintf("KERNEL-%05d", i), Ecosystem: "Debian:bookworm", Package: "linux", Review: true}
	}
	dir, key := fixture(t, false, rows...)
	db, e := database.OpenReader(context.Background(), dir, key)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	r := New(inventory.Snapshot{Host: inventory.Host{Release: map[string]string{"ID": "debian", "VERSION_CODENAME": "bookworm"}}, RunningKernel: &inventory.Kernel{Status: "IDENTIFIED", SourceName: "linux", SourceVersion: "1.0"}, Packages: []inventory.Package{{Manager: "dpkg", Name: "openssl", Version: "1:3.0.14-1~deb12u1"}}})
	if e = Run(context.Background(), &r, db); e != nil {
		t.Fatal(e)
	}
	if r.Confirmed != 1 || r.Review != len(rows) || len(r.Findings) != maxComponentFindings+1 || r.OmittedFindings != len(rows)-maxComponentFindings || r.Components[1].Result != "AFFECTED" || r.Findings[0].Component != "openssl" {
		t.Fatalf("confirmed=%d review=%d retained=%d omitted=%d components=%+v", r.Confirmed, r.Review, len(r.Findings), r.OmittedFindings, r.Components)
	}
}

func TestSignedPolicyPatchOnlyAppliesToMatchingRevision(t *testing.T) {
	dir, key := fixture(t, false, compactdb.Row{Source: "nvd", ID: "CVE-2026-12345", Ecosystem: "CPE", Package: "a:haxx:curl",
		Context: json.RawMessage(`{"cpe":{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:8.0:*:*:*:*:*:*:*"}}}`)})
	db, err := database.OpenReader(context.Background(), dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := inventory.Snapshot{Packages: []inventory.Package{
		{Manager: "homebrew-formula", Name: "fixture-new-formula", Version: "8.0_1", Provenance: "homebrew/core", UpstreamVersion: "8.0"},
		{Manager: "homebrew-formula", Name: "fixture-new-formula", Version: "8.0_2", Provenance: "homebrew/core", UpstreamVersion: "8.0"},
	}}
	r := New(s)
	if err := RunForAdvisories(context.Background(), &r, db, map[string]bool{"CVE-2026-12345": true}); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Version != "8.0_1" {
		t.Fatalf("unexpected findings: %+v", r.Findings)
	}
}

func TestDockerDesktopUsesSignedProductPolicyAndMacApplicability(t *testing.T) {
	const product = productid.DockerDesktop
	if productid.Policy.Bundle["com.docker.docker"] != product || !productid.Known(product) {
		t.Fatal("publisher does not index Docker Desktop")
	}
	rule := func(id, platform, fixed string) compactdb.Row {
		return compactdb.Row{Source: "fixture-nvd", ID: id, Ecosystem: "CPE", Package: product,
			Context: json.RawMessage(fmt.Sprintf(`{"cpe":{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:docker:docker_desktop:*:*:*:*:*:%s:*:*","versionEndExcluding":%q}}}`, platform, fixed))}
	}
	dir, key := fixture(t, false,
		rule("DOCKER-FIXED", "macos", "4.98.0"),
		rule("DOCKER-WINDOWS", "windows", "4.99.0"),
		rule("DOCKER-MAC", "macos", "4.99.0"))
	db, err := database.OpenReader(context.Background(), dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := New(inventory.Snapshot{
		Host: inventory.Host{Release: map[string]string{"ProductVersion": "26.5"}, Architecture: "arm64"},
		Applications: []inventory.Application{
			{Name: "Docker", Identifier: "com.docker.docker", Version: "4.98.0", VersionKind: "release"},
		},
	})
	if err := Run(context.Background(), &r, db); err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "DOCKER-MAC" || r.Confirmed != 1 {
		t.Fatalf("expected only macOS rule covering the installed version: %+v", r.Findings)
	}
}

func TestDockerDesktopLegacyCoverageRequiresSignedProductMarker(t *testing.T) {
	for _, tc := range []struct{ format, want string }{
		{productid.DockerDesktopRuleFormat, "AFFECTED"},
		{"nvd-cpe-v1", "NOT_CHECKED"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			row := compactdb.Row{Source: "fixture-nvd", ID: "DOCKER-LEGACY", Ecosystem: "CPE",
				Package: productid.DockerDesktop, Context: json.RawMessage(`{"cpe":{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:docker:docker_desktop:*:*:*:*:*:macos:*:*","versionEndExcluding":"4.99.0"}}}`)}
			dir, key := fixtureWithCoverage(t, false, false, tc.format, row)
			db, err := database.OpenReader(context.Background(), dir, key)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			report := New(inventory.Snapshot{
				Host: inventory.Host{Release: map[string]string{"ProductVersion": "26.5"}, Architecture: "arm64"},
				Applications: []inventory.Application{
					{Name: "Docker", Identifier: "com.docker.docker", Version: "4.98.0", VersionKind: "release"},
				},
			})
			if err := Run(context.Background(), &report, db); err != nil {
				t.Fatal(err)
			}
			for _, c := range report.Components {
				if c.Origin == "application-bundle" {
					if c.Result != tc.want {
						t.Fatalf("Docker result = %s, want %s", c.Result, tc.want)
					}
					return
				}
			}
			t.Fatal("Docker Desktop was not inventoried")
		})
	}
}
