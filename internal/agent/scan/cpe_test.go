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
	c := components(s, productid.Policy)
	if len(c) != 4 || c[0].Product != productid.Policy.Formula["curl"] || c[0].MatchVersion != "8.0" || c[1].Ecosystem != "" || c[2].Product != productid.Policy.Bundle["com.google.Chrome"] || c[3].Ecosystem != "" {
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
	c := components(s, productid.Policy)
	if len(c) != 1 || c[0].Ecosystem != "" || c[0].Product != "" || c[0].Reason == "" {
		t.Fatal(c)
	}
}

func TestAuditedNVDCorrections(t *testing.T) {
	for _, tc := range []struct {
		product, id, origin, name, installed, upstream, platform, bottle string
		excluded                                                         bool
	}{
		{"a:libssh2:libssh2", "CVE-2026-55200", "homebrew-formula", "libssh2", "1.11.1_7", "1.11.1", "darwin", "", true},
		{"a:libssh2:libssh2", "CVE-2026-55200", "homebrew-formula", "libssh2", "1.11.1_6", "1.11.1", "darwin", "", false},
		{"a:libssh2:libssh2", "CVE-2026-55200", "dpkg", "libssh2", "1.11.1_7", "1.11.1", "linux", "", false},
		{"a:python:python", "CVE-2026-4519", "homebrew-formula", "python@3.11", "3.11.16", "3.11.16", "darwin", "", true},
		{"a:python:python", "CVE-2026-4519", "homebrew-formula", "python@3.11", "3.11.15", "3.11.15", "darwin", "", false},
		{"a:python:python", "CVE-2026-4519", "homebrew-formula", "python@3.13", "3.13.12", "3.13.12", "darwin", "", false},
		{"a:python:python", "CVE-2026-7210", "homebrew-formula", "python@3.11", "3.11.18", "3.11.18", "darwin", "", false},
		{"a:python:python", "CVE-2026-3087", "homebrew-formula", "python@3.11", "3.11.15", "3.11.15", "darwin", "", true},
		{"a:ffmpeg:ffmpeg", "CVE-2025-25468", "homebrew-formula", "ffmpeg", "9.0.2_1", "9.0.2", "darwin", "", true},
		{"a:ffmpeg:ffmpeg", "CVE-2026-107675", "homebrew-formula", "ffmpeg", "9.0.2_1", "9.0.2", "darwin", "", false},
		{"a:ffmpeg:ffmpeg", "CVE-2026-107675", "homebrew-formula", "ffmpeg", "9.0.2_1", "9.0.2", "darwin", "arm64_golden_gate", true},
		{"a:gnu:wget", "CVE-2026-58469", "homebrew-formula", "wget", "1.25.0_2", "1.25.0", "darwin", "", false},
		{"a:gnu:wget", "CVE-2026-58469", "homebrew-formula", "wget", "1.25.0_2", "1.25.0", "darwin", "arm64_golden_gate", true},
	} {
		row := compactdb.Row{Source: "nvd", Package: tc.product, ID: tc.id}
		if got := correctedNVDMatch(productid.Policy, row, tc.origin, tc.name, tc.installed, tc.upstream, tc.platform, tc.bottle); got != tc.excluded {
			t.Errorf("%s on %s %s: excluded=%t, want %t", tc.id, tc.name, tc.installed, got, tc.excluded)
		}
	}
}
