package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"shixpeer.com/ward/internal/agent/scan"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/pkg/inventory"
)

func TestMissingDatabaseSavesIncompleteReport(t *testing.T) {
	dir := t.TempDir()
	collect := func(context.Context) (inventory.Snapshot, error) {
		return inventory.Snapshot{FormatVersion: 1, Collector: "fixture", CollectedAt: time.Now(), Host: inventory.Host{Release: map[string]string{"ProductVersion": "15.2"}}, Coverage: []inventory.Note{}}, nil
	}
	if err := runScan(context.Background(), dir, "", nil, collect); err == nil {
		t.Fatal("missing database reported success")
	}
	var r scan.Report
	if err := atomicfile.ReadJSON(filepath.Join(dir, "report.json"), &r, 1<<20); err != nil {
		t.Fatal(err)
	}
	if r.Status != "incomplete" || r.Database != nil || len(r.Components) != 1 || len(r.Coverage) == 0 {
		t.Fatalf("%+v", r)
	}
	if r.Components[0].Result == "AFFECTED" {
		t.Fatal("false finding")
	}
}
