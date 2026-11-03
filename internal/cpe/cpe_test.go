package cpe

import (
	"encoding/json"
	"testing"
)

func TestExtractionPreservesBooleanContext(t *testing.T) {
	raw := json.RawMessage(`[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:test:app:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]},{"operator":"AND","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:test:app:*:*:*:*:*:*:*:*"},{"vulnerable":false,"criteria":"cpe:2.3:o:test:os:*:*:*:*:*:*:*:*"}]}]},{"negate":true,"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:test:app:1.0:*:*:*:*:*:*:*"}]}]}]`)
	rows, e := Extract(raw)
	if e != nil || len(rows) != 3 {
		t.Fatal(rows, e)
	}
	if rows[0].Complex || !rows[1].Complex || !rows[2].Complex {
		t.Fatal(rows)
	}
	n, e := Parse(rows[0].Match.Criteria)
	if e != nil || n.Key() != "a:test:app" {
		t.Fatal(n, e)
	}
	for _, s := range []string{"cpe:2.3:a:*:app:*:*:*:*:*:*:*:*", "cpe:2.3:a:test:ap?:*:*:*:*:*:*:*:*", `cpe:2.3:a:test:escaped\:product:*:*:*:*:*:*:*:*`, "bad"} {
		if _, e = Parse(s); e == nil {
			t.Fatal("invalid CPE accepted", s)
		}
	}
}
