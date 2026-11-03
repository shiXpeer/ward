// Package catalog compiles streaming source inputs into bounded, indexed files.
package catalog

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/beacon/projection"
	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/filelock"
	"sort"
	"time"
)

type SourceStatus = compactdb.SourceStatus

type Summary struct {
	Format     int                `json:"format"`
	Profile    compactdb.Profile  `json:"profile"`
	Generation string             `json:"generation"`
	Sources    []SourceStatus     `json:"sources"`
	Buckets    []compactdb.Bucket `json:"buckets"`
	Bytes      int64              `json:"bytes"`
	Rows       int64              `json:"rows"`
	CompiledAt time.Time          `json:"compiled_at"`
}
type compiled struct {
	Source string `json:"source,omitempty"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
	Digest string `json:"digest"`
}

func Load(dir string) (Summary, error) {
	var s Summary
	e := atomicfile.ReadJSON(filepath.Join(dir, "catalog.json"), &s, 1<<20)
	if e != nil {
		return s, e
	}
	if s.Format != compactdb.Format || len(s.Buckets) == 0 || len(s.Generation) != 64 {
		return s, errors.New("invalid catalog")
	}
	if _, e := hex.DecodeString(s.Generation); e != nil {
		return s, errors.New("invalid catalog generation")
	}
	if e := s.Profile.Validate(); e != nil {
		return s, e
	}
	for i := range s.Buckets {
		if !compactdb.ValidSlot(s.Buckets[i].Slot) {
			return s, errors.New("invalid catalog slot")
		}
		s.Buckets[i].Path = filepath.Join(dir, "catalogs", s.Generation, s.Buckets[i].Slot+".wdb")
	}
	return s, nil
}
func compile(ctx context.Context, dir string, ss []source.Source, profile compactdb.Profile, retain bool) (Summary, error) {
	var empty Summary
	if e := profile.Validate(); e != nil {
		return empty, e
	}
	if len(ss) == 0 {
		return empty, errors.New("no sources; absence of coverage is not safe")
	}
	unlock, e := filelock.Acquire(ctx, filepath.Join(dir, "compile.lock"), false)
	if e != nil {
		return empty, e
	}
	defer unlock()
	var previous Summary
	updated := map[string]bool{}
	if retain {
		previous, e = Load(dir)
		if e != nil {
			return empty, fmt.Errorf("retaining sources requires a valid existing catalog: %w", e)
		}
		if previous.Profile != profile {
			return empty, errors.New("cannot retain sources across profile changes")
		}
		for _, src := range ss {
			updated[src.ID()] = true
		}
	}
	cache := filepath.Join(dir, "cache")
	if e = os.MkdirAll(cache, 0700); e != nil {
		return empty, e
	}
	var paths, fingerprints, rawPaths []string
	summary := Summary{Format: compactdb.Format, Profile: profile, CompiledAt: time.Now().UTC()}
	for _, src := range ss {
		log.Printf("preparing source=%s", src.ID())
		sourceCtx, sourceCancel := context.WithTimeout(ctx, 20*time.Minute)
		defer sourceCancel()
		ins, e := source.Prepare(sourceCtx, src, filepath.Join(cache, "raw"))
		if e != nil {
			return empty, fmt.Errorf("%s: %w", src.ID(), e)
		}
		status := SourceStatus{ID: src.ID(), Inputs: len(ins), CheckedAt: time.Now().UTC()}
		revisions := make([]string, 0, len(ins))
		for _, in := range ins {
			revisions = append(revisions, in.Digest)
		}
		rb, _ := json.Marshal(revisions)
		status.Revision = compactdb.Digest(rb)
		for _, in := range ins {
			if in.Kind == "nvd-gzip" || in.Kind == "nvd" {
				status.RuleFormats = []string{cpe.RuleFormat}
			}
			rawPaths = append(rawPaths, in.Path)
			rawPaths = append(rawPaths, in.Dependencies...)
			identity, _ := json.Marshal(struct {
				Format                     int
				Profile                    compactdb.Profile
				Source, Kind, Digest, Link string
				Kinds                      []string
			}{projection.Version, profile, src.ID(), in.Kind, in.Digest, in.Link, in.Kinds})
			id := compactdb.Digest(identity)
			path := filepath.Join(cache, id+".rows")
			var meta compiled
			valid := atomicfile.ReadJSON(path+".json", &meta, 8192) == nil
			if st, err := os.Stat(path); err != nil || st.Size() != meta.Bytes {
				valid = false
			}
			if !valid {
				temp, e := os.CreateTemp(cache, "compile-*")
				if e != nil {
					return empty, e
				}
				name := temp.Name()
				gz, _ := gzip.NewWriterLevel(temp, gzip.BestSpeed)
				w := bufio.NewWriterSize(gz, 32<<10)
				put := func(group, key string, value []byte) error {
					slot := compactdb.Slot(group, key)
					if _, e := w.WriteString(slot); e != nil {
						return e
					}
					return compactdb.WriteItem(w, compactdb.Item{Hash: compactdb.KeyHash(group, key), Value: value})
				}
				var count int64
				e = source.Walk(sourceCtx, in, func(a source.Advisory) error {
					count++
					if count > 1500000 {
						return errors.New("source input exceeds advisory bound")
					}
					return projection.Project(profile, src.ID(), a, put)
				})
				if e == nil {
					e = w.Flush()
				}
				if e == nil {
					e = gz.Close()
				}
				if e == nil {
					e = temp.Sync()
				}
				ce := temp.Close()
				if e == nil {
					e = ce
				}
				if e != nil {
					os.Remove(name)
					return empty, fmt.Errorf("%s: %w", src.ID(), e)
				}
				if count == 0 && !in.EmptyOK {
					os.Remove(name)
					return empty, fmt.Errorf("%s: empty source", src.ID())
				}
				if e = os.Rename(name, path); e != nil {
					os.Remove(name)
					return empty, e
				}
				st, e := os.Stat(path)
				if e != nil {
					return empty, e
				}
				meta = compiled{Source: src.ID(), Count: count, Bytes: st.Size(), Digest: id}
				if e = atomicfile.JSON(path+".json", meta); e != nil {
					return empty, e
				}
			} else {
				status.Cached++
			}
			status.Advisories += meta.Count
			paths = append(paths, path)
			fingerprints = append(fingerprints, id)
		}
		if status.Advisories == 0 {
			return empty, fmt.Errorf("%s: source has no advisories", src.ID())
		}
		log.Printf("source=%s advisories=%d inputs=%d cached=%d", status.ID, status.Advisories, status.Inputs, status.Cached)
		summary.Sources = append(summary.Sources, status)
		sourceCancel()
	}
	raw, _ := json.Marshal(struct {
		Format int
		Inputs []string
	}{compactdb.Format, fingerprints})
	if retain {
		for _, status := range previous.Sources {
			if !updated[status.ID] {
				summary.Sources = append(summary.Sources, status)
			}
		}
		sort.Slice(summary.Sources, func(i, j int) bool { return summary.Sources[i].ID < summary.Sources[j].ID })
		facts := []string{}
		for _, status := range summary.Sources {
			facts = append(facts, status.ID+":"+status.Revision+":"+fmt.Sprint(status.RuleFormats))
		}
		raw, _ = json.Marshal(struct {
			Projection int
			Sources    []string
		}{projection.Version, facts})
	}
	summary.Generation = compactdb.Digest(raw)
	if old, e := Load(dir); e == nil && old.Generation == summary.Generation {
		old.Sources = summary.Sources
		if e = atomicfile.JSON(filepath.Join(dir, "catalog.json"), old); e != nil {
			return empty, e
		}
		if !retain {
			prune(dir, old.Generation, paths, rawPaths)
		} else {
			pruneSelectedCache(dir, updated, paths)
		}
		return old, nil
	}
	work, e := os.MkdirTemp(dir, "build-*")
	if e != nil {
		return empty, e
	}
	defer os.RemoveAll(work)
	b, e := compactdb.NewBuilder(filepath.Join(work, "spool"))
	if e != nil {
		return empty, e
	}
	defer b.Close()
	retainedSets := map[[32]byte]bool{}
	if retain {
		for _, bucket := range previous.Buckets {
			if bucket.Slot[0] == 's' {
				continue
			}
			f, err := compactdb.Open(bucket.Path)
			if err != nil {
				return empty, err
			}
			err = f.ScanItems(ctx, func(it compactdb.Item) error {
				var identity struct {
					Source     string `json:"source"`
					VersionSet string `json:"version_set"`
				}
				if err := json.Unmarshal(it.Value, &identity); err != nil {
					return err
				}
				if identity.Source == "" {
					return errors.New("retained row has no source identity")
				}
				if updated[identity.Source] {
					return nil
				}
				if identity.VersionSet != "" {
					retainedSets[compactdb.KeyHash("s", identity.VersionSet)] = true
					if len(retainedSets) > 65536 {
						return errors.New("retained version-set reference budget exceeded")
					}
				}
				return b.PutHash(bucket.Slot, it)
			})
			f.Close()
			if err != nil {
				return empty, err
			}
		}
		for _, bucket := range previous.Buckets {
			if bucket.Slot[0] != 's' {
				continue
			}
			f, err := compactdb.Open(bucket.Path)
			if err != nil {
				return empty, err
			}
			err = f.ScanItems(ctx, func(it compactdb.Item) error {
				if retainedSets[it.Hash] {
					return b.PutHash(bucket.Slot, it)
				}
				return nil
			})
			f.Close()
			if err != nil {
				return empty, err
			}
		}
	}
	for _, path := range paths {
		if e = replay(ctx, path, b); e != nil {
			return empty, e
		}
	}
	summary.Buckets, e = b.Finish(ctx, filepath.Join(work, "db"))
	if e != nil {
		return empty, e
	}
	if len(summary.Buckets) == 0 {
		return empty, errors.New("no compact rows")
	}
	for _, bucket := range summary.Buckets {
		summary.Bytes += bucket.Bytes
		summary.Rows += bucket.Rows
	}
	dest := filepath.Join(dir, "catalogs", summary.Generation)
	if e = os.MkdirAll(filepath.Dir(dest), 0700); e != nil {
		return empty, e
	}
	if _, err := os.Stat(dest); errors.Is(err, os.ErrNotExist) {
		if e = os.Rename(filepath.Join(work, "db"), dest); e != nil {
			return empty, e
		}
	} else if err != nil {
		return empty, err
	}
	for i := range summary.Buckets {
		summary.Buckets[i].Path = filepath.Join(dest, summary.Buckets[i].Slot+".wdb")
	}
	if e = atomicfile.JSON(filepath.Join(dir, "catalog.json"), summary); e != nil {
		return empty, e
	}
	if !retain {
		prune(dir, summary.Generation, paths, rawPaths)
	} else {
		pruneSelectedCache(dir, updated, paths)
		entries, _ := os.ReadDir(filepath.Join(dir, "catalogs"))
		for _, entry := range entries {
			if entry.IsDir() && entry.Name() != summary.Generation {
				os.RemoveAll(filepath.Join(dir, "catalogs", entry.Name()))
			}
		}
	}
	return summary, nil
}
func replay(ctx context.Context, path string, b *compactdb.Builder) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 32<<10)
	magic, _ := r.Peek(2)
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = bufio.NewReaderSize(gz, 32<<10)
	}
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		var slot [4]byte
		_, e = io.ReadFull(r, slot[:])
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		it, e := compactdb.ReadItem(r)
		if e != nil {
			return e
		}
		if e = b.PutHash(string(slot[:]), it); e != nil {
			return e
		}
	}
}

// Sync records failure separately without replacing the last complete catalog.
func Sync(ctx context.Context, dir string, ss []source.Source, profile compactdb.Profile) (Summary, error) {
	return syncSources(ctx, dir, ss, profile, false)
}

// SyncSelected refreshes explicit sources while retaining others and their
// original freshness. It never upgrades old source checked_at timestamps.
func SyncSelected(ctx context.Context, dir string, ss []source.Source, profile compactdb.Profile) (Summary, error) {
	return syncSources(ctx, dir, ss, profile, true)
}
func syncSources(ctx context.Context, dir string, ss []source.Source, profile compactdb.Profile, retain bool) (Summary, error) {
	unlock, e := filelock.Acquire(ctx, filepath.Join(dir, "sync.lock"), false)
	if e != nil {
		return Summary{}, e
	}
	defer unlock()
	s, e := compile(ctx, dir, ss, profile, retain)
	status := struct {
		OK bool      `json:"ok"`
		At time.Time `json:"at"`
	}{e == nil, time.Now().UTC()}
	se := atomicfile.JSON(filepath.Join(dir, "attempt.json"), status)
	if e != nil {
		return s, e
	}
	return s, se
}
func Publication(dir string) (Summary, error) {
	var status struct {
		OK bool      `json:"ok"`
		At time.Time `json:"at"`
	}
	if e := atomicfile.ReadJSON(filepath.Join(dir, "attempt.json"), &status, 4096); e != nil {
		return Summary{}, e
	}
	if !status.OK {
		return Summary{}, errors.New("refusing to publish: last source synchronization failed")
	}
	if time.Since(status.At) > 24*time.Hour {
		return Summary{}, errors.New("source checks older than 24 hours; sync before publishing")
	}
	summary, e := Load(dir)
	if e != nil {
		return Summary{}, e
	}
	for _, src := range summary.Sources {
		if src.CheckedAt.IsZero() || time.Since(src.CheckedAt) > 24*time.Hour {
			return Summary{}, fmt.Errorf("source %s checks older than 24 hours; refresh before publishing", src.ID)
		}
	}
	return summary, nil
}

func prune(dir, generation string, compiledPaths, rawPaths []string) {
	keep := map[string]bool{}
	for _, p := range compiledPaths {
		keep[filepath.Clean(p)] = true
		keep[filepath.Clean(p+".json")] = true
	}
	for _, p := range rawPaths {
		keep[filepath.Clean(p)] = true
		keep[filepath.Clean(p[:len(p)-len(filepath.Ext(p))]+".json")] = true
	}
	cache := filepath.Join(dir, "cache")
	for _, base := range []string{cache, filepath.Join(cache, "raw")} {
		entries, _ := os.ReadDir(base)
		for _, ent := range entries {
			if ent.IsDir() {
				continue
			}
			p := filepath.Join(base, ent.Name())
			if !keep[filepath.Clean(p)] {
				os.Remove(p)
			}
		}
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "catalogs"))
	for _, ent := range entries {
		if ent.IsDir() && ent.Name() != generation {
			os.RemoveAll(filepath.Join(dir, "catalogs", ent.Name()))
		}
	}
}

// Keep only the updated sources' active compiled inputs while preserving other
// sources' caches. Older cache metadata is identified by its first source row.
func pruneSelectedCache(dir string, updated map[string]bool, paths []string) {
	keep := map[string]bool{}
	for _, path := range paths {
		keep[filepath.Clean(path)] = true
	}
	cache := filepath.Join(dir, "cache")
	entries, _ := os.ReadDir(cache)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".rows" {
			continue
		}
		path := filepath.Join(cache, entry.Name())
		if keep[filepath.Clean(path)] {
			continue
		}
		var meta compiled
		_ = atomicfile.ReadJSON(path+".json", &meta, 8192)
		sourceID := meta.Source
		if sourceID == "" {
			sourceID = cacheSource(path)
		}
		if updated[sourceID] {
			_ = os.Remove(path)
			_ = os.Remove(path + ".json")
		}
	}
}
func cacheSource(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	defer gz.Close()
	reader := bufio.NewReaderSize(gz, 4096)
	var slot [4]byte
	if _, err = io.ReadFull(reader, slot[:]); err != nil || slot[0] == 's' {
		return ""
	}
	it, err := compactdb.ReadItem(reader)
	if err != nil {
		return ""
	}
	var row struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(it.Value, &row) != nil {
		return ""
	}
	return row.Source
}
