package compactdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalSortDedupAndLookup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	b, e := NewBuilder(filepath.Join(dir, "spool"))
	if e != nil {
		t.Fatal(e)
	}
	// Force multiple runs and exercise identical keys with distinct provenance.
	for i := 30; i >= 0; i-- {
		v := bytes.Repeat([]byte{byte(i)}, 400000)
		if e = b.Put("p", "same", v); e != nil {
			t.Fatal(e)
		}
		if e = b.Put("p", "same", v); e != nil {
			t.Fatal(e)
		}
	}
	buckets, e := b.Finish(ctx, filepath.Join(dir, "out"))
	if e != nil {
		t.Fatal(e)
	}
	if len(buckets) != 1 || buckets[0].Rows != 31 {
		t.Fatal(buckets)
	}
	f, e := Open(buckets[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Validate(ctx); e != nil {
		t.Fatal(e)
	}
	count := 0
	e = f.Find(ctx, KeyHash("p", "same"), func(v []byte) error {
		if len(v) != 400000 || v[0] != byte(count) {
			t.Fatal("sort mismatch")
		}
		count++
		return nil
	})
	if e != nil || count != 31 {
		t.Fatal(e, count)
	}
	count = 0
	e = f.Find(ctx, KeyHash("p", "absent"), func([]byte) error { count++; return nil })
	if e != nil || count != 0 {
		t.Fatal(e, count)
	}
	f.Close()
	rw, e := os.OpenFile(buckets[0].Path, os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	rw.WriteAt([]byte{255}, HeaderSize+31*IndexSize)
	rw.Close()
	f, e = Open(buckets[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Find(ctx, KeyHash("p", "same"), func([]byte) error { return nil }); e == nil {
		t.Fatal("corrupt body accepted")
	}
}
func TestVersionSetsAndCorruptBounds(t *testing.T) {
	v, e := EncodeVersions([]string{"3", "1", "2", "1"})
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"1", "2", "3"} {
		yes, e := HasVersion(v, s)
		if e != nil || !yes {
			t.Fatal(s, e)
		}
	}
	yes, e := HasVersion(v, "0")
	if yes || e != nil {
		t.Fatal(yes, e)
	}
	if _, e = HasVersion([]byte("WVST\xff\xff\xff\xff"), "1"); e == nil {
		t.Fatal("invalid set accepted")
	}
}

func TestBlockIndexCompressesRowsAndPreservesKeys(t *testing.T) {
	dir := t.TempDir()
	b, e := NewBuilder(filepath.Join(dir, "spool"))
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2000; i++ {
		key := "a"
		if i%2 == 1 {
			key = "b"
		}
		v, _ := json.Marshal(map[string]any{"key": key, "number": i, "padding": string(bytes.Repeat([]byte("x"), 100))})
		if e = b.Put("p", key, v); e != nil {
			t.Fatal(e)
		}
	}
	bs, e := b.Finish(context.Background(), filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	var totalBlocks uint64
	for _, bucket := range bs {
		f, e := Open(bucket.Path)
		if e != nil {
			t.Fatal(e)
		}
		if e = f.Validate(context.Background()); e != nil {
			t.Fatal(e)
		}
		totalBlocks += f.Count
		for _, key := range []string{"a", "b"} {
			n := 0
			e = f.Find(context.Background(), KeyHash("p", key), func(v []byte) error {
				var r struct{ Key string }
				if e := json.Unmarshal(v, &r); e != nil {
					return e
				}
				if r.Key != key {
					t.Fatal("wrong key")
				}
				n++
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if Slot("p", key) == bucket.Slot && n != 1000 {
				t.Fatal(key, n)
			}
		}
		f.Close()
	}
	if totalBlocks >= 20 {
		t.Fatal("index retained every row", totalBlocks)
	}
}

func TestVersionSetUsesSevenBitSlotWithFullHashLookup(t *testing.T) {
	key := ""
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprint(i)
		h := KeyHash("s", candidate)
		if h[0] >= 128 {
			key = candidate
			break
		}
	}
	if key == "" {
		t.Fatal("fixture missing")
	}
	slot := Slot("s", key)
	if !ValidSlot(slot) || slot[2] > '7' {
		t.Fatal(slot)
	}
	dir := t.TempDir()
	b, _ := NewBuilder(filepath.Join(dir, "spool"))
	value, _ := EncodeVersions([]string{"1", "2"})
	b.Put("s", key, value)
	bs, e := b.Finish(context.Background(), filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	f, e := Open(bs[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	found := false
	e = f.Find(context.Background(), KeyHash("s", key), func(raw []byte) error { var e error; found, e = HasVersion(raw, "2"); return e })
	if e != nil || !found {
		t.Fatal(e, found)
	}
}

func TestBuilderCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, _ := NewBuilder(t.TempDir())
	defer b.Close()
	b.Put("p", "key", []byte("value"))
	_, e := b.Finish(ctx, t.TempDir())
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestLookupFiltersDistinctKeysInOneCompressedBlock(t *testing.T) {
	dir := t.TempDir()
	b, _ := NewBuilder(filepath.Join(dir, "spool"))
	var keys []string
	for i := 0; len(keys) < 100; i++ {
		key := fmt.Sprint(i)
		h := KeyHash("v", key)
		if h[0] == 0 {
			keys = append(keys, key)
			for n := 0; n < 2; n++ {
				raw, _ := json.Marshal(map[string]any{"key": key, "n": n})
				if e := b.Put("v", key, raw); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	bs, e := b.Finish(context.Background(), filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	if len(bs) != 1 {
		t.Fatal(bs)
	}
	f, e := Open(bs[0].Path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if f.Count != 1 || f.Rows != 200 {
		t.Fatal(f.Count, f.Rows)
	}
	for _, key := range keys {
		count := 0
		e = f.Find(context.Background(), KeyHash("v", key), func(raw []byte) error {
			var r struct{ Key string }
			if e := json.Unmarshal(raw, &r); e != nil {
				return e
			}
			if r.Key != key {
				t.Fatal("neighbor key leaked")
			}
			count++
			return nil
		})
		if e != nil || count != 2 {
			t.Fatal(e, key, count)
		}
	}
}
