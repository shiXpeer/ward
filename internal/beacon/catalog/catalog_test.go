package catalog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/compactdb"
	"testing"
	"time"
)

func TestCachedCompileFailureAndPruning(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	data := filepath.Join(dir, "input.json")
	config := filepath.Join(dir, "sources.json")
	state := filepath.Join(dir, "state")
	doc := func(fixed string) []byte {
		return []byte(`{"id":"OSV-TEST","modified":"2026-10-30T00:00:00Z","aliases":["CVE-2026-1234"],"database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"` + fixed + `"}]}]}]}`)
	}
	os.WriteFile(data, doc("1.0.0"), 0600)
	cfg, _ := json.Marshal(source.Config{Sources: []source.Definition{{ID: "fixture", Type: "osv", Path: data, Enabled: true}}})
	os.WriteFile(config, cfg, 0600)
	ss, e := source.Load(config)
	if e != nil {
		t.Fatal(e)
	}
	first, e := Sync(ctx, state, ss, compactdb.All)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Sync(ctx, state, ss, compactdb.All)
	if e != nil || again.Generation != first.Generation || again.Sources[0].Cached != 1 {
		t.Fatal(e, again)
	}
	rows, _ := filepath.Glob(filepath.Join(state, "cache", "*.rows"))
	raw, _ := os.ReadFile(rows[0])
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		t.Fatal("compiled cache not compressed")
	}
	news, e := News(ctx, state)
	if e != nil || len(news) != 1 {
		t.Fatal(e, len(news))
	}
	os.WriteFile(data, []byte("broken"), 0600)
	if _, e = Sync(ctx, state, ss, compactdb.All); e == nil {
		t.Fatal("bad source accepted")
	}
	if _, e = Publication(state); e == nil {
		t.Fatal("failed sync publishable")
	}
	saved, e := Load(state)
	if e != nil || saved.Generation != first.Generation {
		t.Fatal("last good catalog lost", e)
	}
	os.WriteFile(data, doc("2.0.0"), 0600)
	second, e := Sync(ctx, state, ss, compactdb.All)
	if e != nil || second.Generation == first.Generation {
		t.Fatal(e)
	}
	if _, e = Publication(state); e != nil {
		t.Fatal(e)
	}
	dirs, _ := os.ReadDir(filepath.Join(state, "catalogs"))
	rows, _ = filepath.Glob(filepath.Join(state, "cache", "*.rows"))
	if len(dirs) != 1 || len(rows) != 1 {
		t.Fatal("obsolete private state retained", len(dirs), len(rows))
	}
}

func TestSelectedRefreshRetainsCoverageAliasKeysAndFreshness(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	doc := func(id, version string) []byte {
		return []byte(`{"id":"` + id + `","modified":"2026-10-30T00:00:00Z","aliases":["ALIAS-` + id + `"],"affected":[{"package":{"ecosystem":"npm","name":"example"},"versions":["` + version + `"]}]}`)
	}
	paths := []string{filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")}
	for i, id := range []string{"A", "B"} {
		os.WriteFile(paths[i], doc(id, "1.0.0"), 0600)
	}
	load := func(defs []source.Definition) []source.Source {
		config := filepath.Join(dir, "config.json")
		raw, _ := json.Marshal(source.Config{Sources: defs})
		os.WriteFile(config, raw, 0600)
		ss, e := source.Load(config)
		if e != nil {
			t.Fatal(e)
		}
		return ss
	}
	defs := []source.Definition{{ID: "a", Type: "osv", Path: paths[0], Enabled: true}, {ID: "b", Type: "osv", Path: paths[1], Enabled: true}}
	old, e := Sync(ctx, state, load(defs), compactdb.All)
	if e != nil {
		t.Fatal(e)
	}
	oldCheck := old.Sources[1].CheckedAt
	os.WriteFile(paths[0], doc("A", "2.0.0"), 0600)
	fresh, e := SyncSelected(ctx, state, load(defs[:1]), compactdb.All)
	if e != nil {
		t.Fatal(e)
	}
	if len(fresh.Sources) != 2 || !fresh.Sources[1].CheckedAt.Equal(oldCheck) {
		t.Fatal("retained freshness changed", fresh.Sources)
	}
	caches, _ := filepath.Glob(filepath.Join(state, "cache", "*.rows"))
	if len(caches) != 2 {
		t.Fatal("selected refresh retained obsolete caches or deleted other sources", len(caches))
	}
	foundAlias := false
	foundNew := false
	foundOld := false
	for _, bucket := range fresh.Buckets {
		f, e := compactdb.Open(bucket.Path)
		if e != nil {
			t.Fatal(e)
		}
		if bucket.Slot == compactdb.Slot("v", "ALIAS-B") {
			e = f.Find(ctx, compactdb.KeyHash("v", "ALIAS-B"), func(raw []byte) error {
				var r compactdb.Row
				json.Unmarshal(raw, &r)
				if r.ID == "B" {
					foundAlias = true
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		if bucket.Slot == compactdb.Slot("p", compactdb.PackageKey("npm", "example")) {
			e = f.Scan(ctx, func(raw []byte) error {
				var r compactdb.Row
				json.Unmarshal(raw, &r)
				if r.Source == "a" && len(r.Versions) > 0 {
					foundNew = foundNew || r.Versions[0] == "2.0.0"
					foundOld = foundOld || r.Versions[0] == "1.0.0"
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		}
		f.Close()
	}
	if !foundAlias || !foundNew || foundOld {
		t.Fatal(foundAlias, foundNew, foundOld)
	}
	same, e := SyncSelected(ctx, state, load(defs[:1]), compactdb.All)
	if e != nil || same.Generation != fresh.Generation {
		t.Fatal("unchanged refresh rebuilt", e)
	}
	os.WriteFile(paths[0], []byte("broken"), 0600)
	if _, e = SyncSelected(ctx, state, load(defs[:1]), compactdb.All); e == nil {
		t.Fatal("bad subset accepted")
	}
	saved, e := Load(state)
	if e != nil || saved.Generation != fresh.Generation {
		t.Fatal("last good catalog changed", e)
	}
	if _, e = Publication(state); e == nil {
		t.Fatal("failed refresh publishable")
	}
}

func TestPublicationChecksRetainedSourceAge(t *testing.T) {
	dir := t.TempDir()
	// Publication must reject stale retained sources even after a recent selected sync.
	s := Summary{Format: compactdb.Format, Profile: compactdb.All, Generation: compactdb.Digest([]byte("test")), Buckets: []compactdb.Bucket{{Slot: "p-00"}}, Sources: []SourceStatus{{ID: "old", CheckedAt: time.Now().Add(-25 * time.Hour)}}}
	if err := atomicfile.JSON(filepath.Join(dir, "catalog.json"), s); err != nil {
		t.Fatal(err)
	}
	status := struct {
		OK bool      `json:"ok"`
		At time.Time `json:"at"`
	}{true, time.Now()}
	if err := atomicfile.JSON(filepath.Join(dir, "attempt.json"), status); err != nil {
		t.Fatal(err)
	}
	if _, err := Publication(dir); err == nil {
		t.Fatal("stale retained source published")
	}
}
