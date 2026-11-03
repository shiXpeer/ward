package projection

import (
	"encoding/json"
	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/pkg/vuln"
	"testing"
)

func TestProjectionNeverDropsUncoveredVersionsOrConditions(t *testing.T) {
	ranges := []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2:1.0-2"}}}}
	for _, tc := range []struct {
		versions []string
		drop     bool
	}{{[]string{"1:9.0-1", "2:1.0-1~bpo1"}, true}, {[]string{"2:1.0-2"}, false}, {[]string{"broken"}, false}} {
		a := source.Advisory{ID: "CVE-test", Affected: []source.Affected{{Ecosystem: "Debian:bookworm", Name: "pkg", Ranges: ranges, Versions: tc.versions, EcosystemSpecific: json.RawMessage(`{"unknown_condition":true}`)}}}
		var row compactdb.Row
		e := Project(compactdb.All, "vendor", a, func(g, k string, b []byte) error {
			if g == "p" {
				return json.Unmarshal(b, &row)
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		if (len(row.Versions) == 0) != tc.drop || !row.Review || !row.SourcePackage {
			t.Fatal(row)
		}
	}
}
func TestNotAffectedAndCancellation(t *testing.T) {
	a := source.Advisory{ID: "CVE-x", Affected: []source.Affected{{Ecosystem: "Debian:bookworm", Name: "x", EcosystemSpecific: json.RawMessage(`{"status":"resolved","fixed_version":"0"}`)}}}
	e := Project(compactdb.All, "debian", a, func(g, k string, b []byte) error {
		if g == "p" {
			var r compactdb.Row
			json.Unmarshal(b, &r)
			if r.Status != "not_affected" || len(r.Ranges) != 0 || r.Review {
				t.Fatal(r)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestRangeSpecificConditionsAndMalformedEventsRemainExplicit(t *testing.T) {
	for _, rg := range []vuln.Range{{Type: "ECOSYSTEM", DatabaseSpecific: json.RawMessage(`{"condition":"vendor-defined"}`), Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: "2"}}}, {Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0", Fixed: "2"}}}, {Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {}}}} {
		a := source.Advisory{ID: "test", Affected: []source.Affected{{Ecosystem: "Debian:bookworm", Name: "package", Ranges: []vuln.Range{rg}, Versions: []string{"1"}}}}
		e := Project(compactdb.All, "vendor", a, func(g, k string, b []byte) error {
			if g == "p" {
				var r compactdb.Row
				if e := json.Unmarshal(b, &r); e != nil {
					return e
				}
				if len(r.Versions) != 1 {
					t.Fatal("dropped a version without proof")
				}
				if len(rg.DatabaseSpecific) > 0 && !r.Review {
					t.Fatal("unrepresented condition not flagged")
				}
			}
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
	}
}

func TestCPELeavesSurviveProjectionWithConditions(t *testing.T) {
	a := source.Advisory{ID: "CVE-test", Affected: []source.Affected{{Ecosystem: "CPE", Name: "a:haxx:curl", DatabaseSpecific: json.RawMessage(`{"match":{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.0.1"},"complex":true}`)}}}
	count := 0
	err := Project(compactdb.All, "custom-nvd", a, func(group, key string, raw []byte) error {
		if group != "p" {
			return nil
		}
		count++
		var r compactdb.Row
		if e := json.Unmarshal(raw, &r); e != nil {
			return e
		}
		if key != compactdb.PackageKey("CPE", "a:haxx:curl") || !r.Review || len(r.Context) == 0 || len(r.Ranges) > 0 {
			t.Fatal(r, key)
		}
		return nil
	})
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
}
