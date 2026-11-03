package scan

import (
	"encoding/json"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/productid"
	"shixpeer.com/ward/pkg/inventory"
	"testing"
)

func TestCPEVersionAndPlatformConstraints(t *testing.T) {
	cases := []struct {
		name, version, criteria string
		change                  func(*cpe.Rule)
		want                    string
	}{
		{"affected", "1.5", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", nil, "affected"},
		{"fixed boundary", "2.0", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", nil, "excluded"},
		{"wrong platform", "1.5", "cpe:2.3:a:test:app:*:*:*:*:*:windows:*:*", nil, "excluded"},
		{"mac platform", "1.5", "cpe:2.3:a:test:app:*:*:*:*:*:mac_os_x:*:*", nil, "affected"},
		{"edition unknown", "1.5", "cpe:2.3:a:test:app:*:*:enterprise:*:*:*:*:*", nil, "review"},
		{"complex tree", "1.5", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", func(r *cpe.Rule) { r.Complex = true }, "review"},
		{"prerelease unsupported", "1.5rc1", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", nil, "review"},
		{"upper inclusive", "2.0", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", func(r *cpe.Rule) { r.Match.EndIncluding = "2.0"; r.Match.EndExcluding = "" }, "affected"},
		{"lower exclusive", "1.0", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", func(r *cpe.Rule) { r.Match.StartIncluding = ""; r.Match.StartExcluding = "1.0" }, "excluded"},
		{"conflicting bounds", "1.5", "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", func(r *cpe.Rule) { r.Match.StartExcluding = "1.0" }, "review"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rule := cpe.Rule{Match: cpe.Match{Vulnerable: true, Criteria: c.criteria, StartIncluding: "1.0", EndExcluding: "2.0"}}
			if c.change != nil {
				c.change(&rule)
			}
			raw, _ := json.Marshal(map[string]any{"cpe": rule})
			got := evaluateCPE(compactdb.Row{Package: "a:test:app", Context: raw}, c.version, "darwin", "arm64")
			if got.state != c.want {
				t.Fatal(got)
			}
		})
	}
}
func TestIdentitiesRequireReceiptOrBundleID(t *testing.T) {
	s := inventory.Snapshot{Packages: []inventory.Package{
		{Manager: "homebrew-formula", Name: "curl", Version: "8.0_1", Provenance: "homebrew/core", UpstreamVersion: "8.0"},
		{Manager: "homebrew-formula", Name: "curl", Version: "8.0_1", Provenance: "custom/tap", UpstreamVersion: "8.0"},
	}, Applications: []inventory.Application{{Name: "Renamed Browser", Identifier: "com.google.Chrome", Version: "120.0.1.2", VersionKind: "release"}, {Name: "Google Chrome", Identifier: "other.app", Version: "120.0.1.2"}}}
	c := components(s)
	if len(c) != 4 || c[0].Product != productid.Formula["curl"] || c[0].MatchVersion != "8.0" || c[1].Ecosystem != "" || c[2].Product != productid.Bundle["com.google.Chrome"] || c[3].Ecosystem != "" {
		t.Fatal(c)
	}
}

func TestComplexOldVersionsCanBeExcludedButNegationCannot(t *testing.T) {
	rule := cpe.Rule{Complex: true, Match: cpe.Match{Vulnerable: true, Criteria: "cpe:2.3:a:test:app:*:*:*:*:*:*:*:*", EndExcluding: "2.0"}}
	raw, _ := json.Marshal(map[string]any{"cpe": rule})
	if got := evaluateCPE(compactdb.Row{Package: "a:test:app", Review: true, Context: raw}, "3.0", "darwin", "arm64"); got.state != "excluded" {
		t.Fatal(got)
	}
	rule.Negated = true
	raw, _ = json.Marshal(map[string]any{"cpe": rule})
	if got := evaluateCPE(compactdb.Row{Package: "a:test:app", Review: true, Context: raw}, "3.0", "darwin", "arm64"); got.state != "review" {
		t.Fatal(got)
	}
}

func TestBundleBuildNumberDoesNotBecomeReleaseVersion(t *testing.T) {
	s := inventory.Snapshot{Applications: []inventory.Application{{Name: "Browser", Identifier: "com.google.Chrome", Version: "999999", VersionKind: "build"}}}
	c := components(s)
	if len(c) != 1 || c[0].Ecosystem != "" || c[0].Product != "" || c[0].Reason == "" {
		t.Fatal(c)
	}
}
