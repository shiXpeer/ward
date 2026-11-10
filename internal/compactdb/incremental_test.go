package compactdb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFinishIncrementalReusesIdenticalShardAndHandlesDeletions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	names := []string{"unchanged", "partially-deleted", "removed"}
	if Slot("p", names[0]) == Slot("p", names[1]) || Slot("p", names[0]) == Slot("p", names[2]) ||
		Slot("p", names[1]) == Slot("p", names[2]) {
		t.Fatal("fixture keys must occupy distinct shards")
	}
	build := func(generation string, previous []Bucket, initial bool) ([]Bucket, int) {
		t.Helper()
		b, err := NewBuilder(filepath.Join(dir, generation+"-spool"))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range names[:2] {
			if err := b.Put("p", key, []byte("kept")); err != nil {
				t.Fatal(err)
			}
		}
		if initial {
			for _, key := range names[1:] {
				if err := b.Put("p", key, []byte("deleted")); err != nil {
					t.Fatal(err)
				}
			}
		}
		result, reused, err := b.FinishIncremental(ctx, filepath.Join(dir, generation), previous)
		if err != nil {
			t.Fatal(err)
		}
		return result, reused
	}
	old, _ := build("old", nil, true)
	next, reused := build("next", old, false)
	if reused != 1 || len(next) != 2 {
		t.Fatalf("reused=%d next=%v", reused, next)
	}
	for _, bucket := range next {
		if bucket.Rows != 1 || bucket.Slot == Slot("p", names[2]) {
			t.Fatalf("deleted row survived: %+v", bucket)
		}
		if bucket.Slot == Slot("p", names[0]) {
			a, err := os.Stat(filepath.Join(dir, "old", bucket.Slot+".wdb"))
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.Stat(bucket.Path)
			if err != nil || !os.SameFile(a, b) {
				t.Fatal("unchanged shard was rebuilt")
			}
		}
	}
}
