package scan

import (
	"encoding/json"
	"testing"

	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/debversion"
	"shixpeer.com/ward/pkg/vuln"
)

func TestDebianRanges(t *testing.T) {
	cases := []struct {
		name, version string
		events        []vuln.RangeEvent
		match, bad    bool
	}{
		{"epoch backport vulnerable", "1:3.0.14-1~deb12u1", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "1:3.0.14-1~deb12u2"}}, true, false},
		{"fixed boundary", "1:3.0.14-1~deb12u2", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "1:3.0.14-1~deb12u2"}}, false, false},
		{"epoch newer", "2:1.0-1", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "1:3.0-1"}}, false, false},
		{"last affected inclusive", "1.2-3", []vuln.RangeEvent{{Introduced: "1.0"}, {LastAffected: "1.2-3"}}, true, false},
		{"limit exclusive", "1.2-3", []vuln.RangeEvent{{Introduced: "1.0"}, {Limit: "1.2-3"}}, false, false},
		{"gap", "2.5", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0"}, {Introduced: "3.0"}, {Fixed: "4.0"}}, false, false},
		{"second interval", "3.5", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0"}, {Introduced: "3.0"}, {Fixed: "4.0"}}, true, false},
		{"open interval", "5.0", []vuln.RangeEvent{{Introduced: "3.0"}}, true, false},
		{"mixed event", "1.0", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0", LastAffected: "3.0"}}, false, true},
		{"malformed after match", "1.0", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0"}, {Fixed: "3.0"}}, false, true},
		{"descending interval", "1.0", []vuln.RangeEvent{{Introduced: "2.0"}, {Fixed: "1.0"}}, false, true},
		{"overlap", "1.0", []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0"}, {Introduced: "1.5"}}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			yes, _, err := inRange(c.version, vuln.Range{Type: "ECOSYSTEM", Events: c.events}, debversion.Compare)
			if (err != nil) != c.bad || yes != c.match {
				t.Fatalf("got %v, %v", yes, err)
			}
		})
	}
}
func TestUnsupportedAndWithdrawnNeverConfirmed(t *testing.T) {
	base := compactdb.Row{Ecosystem: "Debian:bookworm", Ranges: []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0"}}}}}
	cases := []struct {
		name   string
		change func(*compactdb.Row)
		want   string
	}{
		{"supported", func(r *compactdb.Row) {}, "affected"},
		{"withdrawn", func(r *compactdb.Row) { r.Withdrawn = true }, "excluded"},
		{"not affected", func(r *compactdb.Row) { r.Status = "not_affected" }, "excluded"},
		{"review flag", func(r *compactdb.Row) { r.Review = true }, "review"},
		{"unknown ecosystem", func(r *compactdb.Row) { r.Ecosystem = "Homebrew" }, "review"},
		{"git", func(r *compactdb.Row) { r.Ranges[0].Type = "GIT" }, "review"},
		{"unsupported condition", func(r *compactdb.Row) { r.Context = json.RawMessage(`{"module_name_regex":"other"}`) }, "review"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			r.Ranges = append([]vuln.Range{}, base.Ranges...)
			c.change(&r)
			if got := evaluate(r, "1.0", false); got.state != c.want {
				t.Fatal(got)
			}
		})
	}
	exact := compactdb.Row{Ecosystem: "Debian:bookworm", Versions: []string{"1.0"}}
	if evaluate(exact, "1.0", true).state != "affected" {
		t.Fatal("exact version ignored")
	}
}
func TestMacOSReleaseIsReviewNotProof(t *testing.T) {
	r := compactdb.Row{Ecosystem: "macOS", Context: json.RawMessage(`{"fixed_version":"15.3","applicability":"vendor-bulletin-review-required"}`)}
	for _, c := range []struct{ v, want string }{{"15.2", "review"}, {"15.3", "excluded"}, {"15.4", "excluded"}, {"14.9", "excluded"}, {"15.beta", "review"}} {
		if got := evaluate(r, c.v, false); got.state != c.want {
			t.Fatalf("%s: %v", c.v, got)
		}
	}
}

func TestGlobalLanguageRules(t *testing.T) {
	for _, eco := range []string{"npm", "PyPI"} {
		typ := "ECOSYSTEM"
		if eco == "npm" {
			typ = "SEMVER"
		}
		r := compactdb.Row{Ecosystem: eco, Ranges: []vuln.Range{{Type: typ, Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2.0.0"}}}}}
		if d := evaluate(r, "1.0.0", false); d.state != "affected" {
			t.Fatal(eco, d)
		}
		if d := evaluate(r, "2.0.0", false); d.state != "excluded" {
			t.Fatal(eco, d)
		}
		if d := evaluate(r, "1.0.0rc1", false); d.state != "review" {
			t.Fatal(eco, d)
		}
	}
}

func TestCanonicalUnfixedAmbiguityAndPublicFix(t *testing.T) {
	r := compactdb.Row{ID: "UBUNTU-CVE-2026-1234", Ecosystem: "Ubuntu:22.04:LTS", Context: json.RawMessage(`{"availability":"No subscription required"}`), Ranges: []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}}}}}
	if d := evaluate(r, "1.0", true); d.state != "review" {
		t.Fatal(d)
	}
	r.Ranges[0].Events = append(r.Ranges[0].Events, vuln.RangeEvent{Fixed: "2.0"})
	if d := evaluate(r, "1.0", false); d.state != "affected" || len(d.fixed) != 1 {
		t.Fatal(d)
	}
	if d := evaluate(r, "2.0", false); d.state != "excluded" {
		t.Fatal(d)
	}
}
