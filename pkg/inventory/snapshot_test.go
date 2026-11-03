package inventory

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSnapshotJSONOmitsUncheckedSections(t *testing.T) {
	snap := Snapshot{
		FormatVersion:    FormatVersion,
		Collector:        "hostagent",
		CollectorVersion: "0.1.0",
		CollectedAt:      time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		Host:             Host{Uname: "Linux 6.8.0 x86_64", UIDClass: "unprivileged"},
		Coverage:         []Note{{Code: NotChecked, Source: "packages", Detail: "not yet"}},
	}
	if err := snap.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"packages", "hostname", "listeners"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("snapshot JSON contains %s: %s", key, raw)
		}
	}
	if _, ok := fields["coverage"]; !ok {
		t.Fatalf("coverage missing: %s", raw)
	}
}

func TestSnapshotValidateRejectsUnknownFormat(t *testing.T) {
	snap := Snapshot{FormatVersion: 2, Collector: "hostagent", CollectedAt: time.Now(), Coverage: []Note{}}
	if err := snap.Validate(); err == nil {
		t.Fatal("expected format error")
	}
}
