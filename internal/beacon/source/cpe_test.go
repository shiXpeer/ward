package source

import (
	"encoding/json"
	"shixpeer.com/ward/internal/cpe"
	"testing"
)

func TestNVDExplicitProductMappingAndBooleanEvidence(t *testing.T) {
	raw := json.RawMessage(`{"id":"CVE-2026-1234","lastModified":"2026-10-30T00:00:00Z","configurations":[{"operator":"AND","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","versionEndExcluding":"8.0.1"},{"vulnerable":true,"criteria":"cpe:2.3:a:unmapped:other:*:*:*:*:*:*:*:*"},{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"}]}]}]}`)
	a, e := parseNVDRecord(raw)
	if e != nil || len(a.Affected) != 1 || a.UnmappedAffected != 1 {
		t.Fatal(a, e)
	}
	var rule cpe.Rule
	if e = json.Unmarshal(a.Affected[0].DatabaseSpecific, &rule); e != nil || !rule.Complex || rule.Match.EndExcluding != "8.0.1" {
		t.Fatal(rule, e)
	}
	if a.Affected[0].Ecosystem != "CPE" || a.Affected[0].Name != "a:haxx:curl" {
		t.Fatal(a.Affected)
	}
}
