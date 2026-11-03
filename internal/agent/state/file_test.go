package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"shixpeer.com/ward/pkg/inventory"
)

func TestFileRoundTripIsPrivate(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snap := inventory.Snapshot{
		FormatVersion:    inventory.FormatVersion,
		Collector:        "hostagent",
		CollectorVersion: "0.1.0",
		CollectedAt:      time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
		Coverage:         []inventory.Note{},
	}
	ctx := context.Background()
	if err := store.SaveSnapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	loadedSnap, err := store.LoadSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if loadedSnap.Collector != "hostagent" {
		t.Fatal(loadedSnap.Collector)
	}
	for _, name := range []string{SnapshotFile} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", name, info.Mode().Perm())
		}
	}
}
