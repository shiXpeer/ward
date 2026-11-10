package database

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/beacon/catalog"
	"shixpeer.com/ward/internal/beacon/exporter"
	"shixpeer.com/ward/internal/beacon/publish"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/snapshot"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func makeCatalog(t *testing.T, dir, version string) catalog.Summary {
	t.Helper()
	b, e := compactdb.NewBuilder(filepath.Join(dir, "spool"))
	if e != nil {
		t.Fatal(e)
	}
	b.Put("p", compactdb.PackageKey("Debian:bookworm", "openssl"), []byte(`{"source":"vendor","id":"CVE-TEST","version":"`+version+`"}`))
	b.Put("r", "CVE-TEST", []byte(`{"id":"CVE-TEST","epss":0.9}`))
	bs, e := b.Finish(context.Background(), filepath.Join(dir, "db"))
	if e != nil {
		t.Fatal(e)
	}
	return catalog.Summary{Format: compactdb.Format, Profile: compactdb.All, Generation: snapshot.Digest([]byte(version)), Buckets: bs, Sources: []catalog.SourceStatus{{ID: "fixture", Advisories: 1, CheckedAt: time.Now()}}}
}
func TestStreamInstallIncrementalLookupAndTamper(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	public := filepath.Join(dir, "public")
	now := time.Now().UTC()
	first := makeCatalog(t, filepath.Join(dir, "first"), "1")
	m, e := exporter.Export(ctx, public, first, key, "", time.Hour, now)
	if e != nil {
		t.Fatal(e)
	}
	var requests atomic.Int64
	handler := publish.Artifacts(public)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/manifest.json" {
			requests.Add(1)
		}
		if strings.Contains(r.URL.RawQuery, "openssl") {
			t.Error("inventory sent")
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	c := Client{URL: server.URL + "/v1/manifest.json", HTTP: server.Client(), TrustedKey: pub, Dir: filepath.Join(dir, "agent")}
	result, e := c.Update(ctx)
	if e != nil || result.Downloaded != 2 || !result.NewRevision {
		t.Fatal(result, e)
	}
	before, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	n := 0
	e = Lookup(ctx, c.Dir, "p", compactdb.PackageKey("Debian:bookworm", "openssl"), 100, func(b []byte) error { n++; var v map[string]string; return json.Unmarshal(b, &v) })
	if e != nil || n != 1 {
		t.Fatal(e, n)
	}
	requests.Store(0)
	result, e = c.Update(ctx)
	if e != nil || result.Downloaded != 0 || requests.Load() != 0 || result.NewRevision {
		t.Fatal(result, e, requests.Load())
	}
	second := makeCatalog(t, filepath.Join(dir, "second"), "2")
	m2, e := exporter.Export(ctx, public, second, key, "", time.Hour, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	result, e = c.Check(ctx)
	if e != nil || !result.Changed || result.NewRevision || result.Revision != m2.Revision || result.Downloaded != 0 || requests.Load() != 0 {
		t.Fatal("manifest-only check did not report the new revision without downloading", result, e, requests.Load())
	}
	unchanged, e := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	if e != nil || string(before) != string(unchanged) {
		t.Fatal("manifest-only check changed the installed database", e)
	}
	var changed snapshot.Object
	for _, o := range m2.Objects {
		if o.Slot[0] == 'p' {
			changed = o
		}
	}
	path := filepath.Join(public, changed.Name())
	data, _ := os.ReadFile(path)
	data[len(data)/2] ^= 1
	os.WriteFile(path, data, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("tampered object accepted")
	}
	after, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	if string(before) != string(after) {
		t.Fatal("failed update advanced current/checkpoint")
	}
	data[len(data)/2] ^= 1
	os.WriteFile(path, data, 0644)
	requests.Store(0)
	var progress []Progress
	c.OnProgress = func(event Progress) { progress = append(progress, event) }
	result, e = c.Update(ctx)
	if e != nil || result.Downloaded != 1 || requests.Load() != 1 || !result.NewRevision {
		t.Fatal(result, e, requests.Load())
	}
	if len(progress) < 5 || progress[0].Stage != "manifest" || progress[1].Stage != "planning" {
		t.Fatalf("unexpected update stages: %+v", progress)
	}
	for _, event := range progress[2 : len(progress)-1] {
		if event.Stage != "download" || event.Component != changed.Slot ||
			event.Total != changed.Bytes || event.Done < 0 || event.Done > event.Total {
			t.Fatalf("unexpected download progress: %+v", event)
		}
	}
	if first, last := progress[2], progress[len(progress)-1]; first.Done != 0 ||
		last.Stage != "install" || last.Done != changed.Bytes || last.Total != changed.Bytes {
		t.Fatalf("unexpected download bounds: first=%+v last=%+v", first, last)
	}
	old, _ := snapshot.Sign(m, key)
	atomicfile.Write(filepath.Join(public, "manifest.json"), old, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("rollback accepted")
	}
	if _, e = c.Check(ctx); e == nil {
		t.Fatal("manifest-only check accepted a rollback")
	}
	conflict := m2
	conflict.Generation = snapshot.Digest([]byte("conflict"))
	signed, _ := snapshot.Sign(conflict, key)
	atomicfile.Write(filepath.Join(public, "manifest.json"), signed, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("conflicting revision accepted")
	}
	expired := m2
	expired.CreatedAt = now.Add(-2 * time.Hour)
	expired.ExpiresAt = now.Add(-time.Hour)
	signed, _ = snapshot.Sign(expired, key)
	atomicfile.Write(filepath.Join(public, "manifest.json"), signed, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("expired accepted")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ = snapshot.Sign(m2, other)
	atomicfile.Write(filepath.Join(public, "manifest.json"), signed, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("wrong signature accepted")
	}
}
func TestExpiryDuringDownloadAndInvalidScheme(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := makeCatalog(t, filepath.Join(dir, "data"), "1")
	public := filepath.Join(dir, "public")
	now := time.Now().UTC()
	exporter.Export(ctx, public, s, key, "", time.Minute, now)
	h := publish.Artifacts(public)
	server := httptest.NewTLSServer(h)
	defer server.Close()
	calls := 0
	c := Client{Dir: filepath.Join(dir, "agent"), URL: server.URL + "/v1/manifest.json", HTTP: server.Client(), TrustedKey: pub, Now: func() time.Time {
		calls++
		if calls >= 3 {
			return now.Add(2 * time.Minute)
		}
		return now
	}}
	if _, e := c.Update(ctx); e == nil {
		t.Fatal("expiry while downloading accepted")
	}
	if _, e := os.Stat(filepath.Join(c.Dir, "current.json")); !os.IsNotExist(e) {
		t.Fatal("checkpoint installed", e)
	}
	c.URL = "http://127.0.0.1/manifest.json"
	if _, e := c.Update(ctx); e == nil {
		t.Fatal("HTTP accepted")
	}
}

func TestEquivalentEnvelopeDoesNotConflict(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := makeCatalog(t, filepath.Join(dir, "data"), "1")
	public := filepath.Join(dir, "public")
	exporter.Export(ctx, public, s, key, "", time.Hour, time.Now())
	server := httptest.NewTLSServer(publish.Artifacts(public))
	defer server.Close()
	c := Client{URL: server.URL + "/v1/manifest.json", HTTP: server.Client(), TrustedKey: pub, Dir: filepath.Join(dir, "agent")}
	if _, e := c.Update(ctx); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(public, "manifest.json"))
	var env snapshot.Envelope
	json.Unmarshal(raw, &env)
	pretty, _ := json.MarshalIndent(env, "", "  ")
	os.WriteFile(filepath.Join(public, "manifest.json"), pretty, 0644)
	r, e := c.Update(ctx)
	if e != nil || r.Downloaded != 0 {
		t.Fatal("equivalent authenticated payload rejected", e)
	}
}

func TestLastObjectFailurePreservesInstalledGeneration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	public := filepath.Join(dir, "public")
	first := makeCatalog(t, filepath.Join(dir, "one"), "1")
	now := time.Now()
	exporter.Export(ctx, public, first, key, "", time.Hour, now)
	srv := httptest.NewTLSServer(publish.Artifacts(public))
	defer srv.Close()
	c := Client{Dir: filepath.Join(dir, "agent"), URL: srv.URL + "/v1/manifest.json", HTTP: srv.Client(), TrustedKey: pub}
	if _, e := c.Update(ctx); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	b, _ := compactdb.NewBuilder(filepath.Join(dir, "two-spool"))
	b.Put("p", compactdb.PackageKey("Debian:bookworm", "openssl"), []byte(`{"id":"new"}`))
	b.Put("r", "CVE-TEST", []byte(`{"id":"new","epss":0.5}`))
	bs, e := b.Finish(ctx, filepath.Join(dir, "two-db"))
	if e != nil {
		t.Fatal(e)
	}
	second := first
	second.Generation = snapshot.Digest([]byte("two"))
	second.Buckets = bs
	m, e := exporter.Export(ctx, public, second, key, "", time.Hour, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	last := m.Objects[len(m.Objects)-1]
	path := filepath.Join(public, last.Name())
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 1
	os.WriteFile(path, raw, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("tampered last object accepted")
	}
	after, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	if string(before) != string(after) {
		t.Fatal("partial update committed")
	}
	count := 0
	if e = Lookup(ctx, c.Dir, "p", compactdb.PackageKey("Debian:bookworm", "openssl"), 100, func(v []byte) error {
		count++
		if strings.Contains(string(v), `"id":"new"`) {
			t.Fatal("new incomplete generation visible")
		}
		return nil
	}); e != nil || count != 1 {
		t.Fatal(e, count)
	}
	os.WriteFile(filepath.Join(c.Dir, "objects", "orphan.wdb"), []byte("orphan"), 0600)
	raw[len(raw)/2] ^= 1
	os.WriteFile(path, raw, 0644)
	r, e := c.Update(ctx)
	if e != nil || r.Downloaded != 1 {
		t.Fatal("valid partial object not reused", e, r)
	}
	if _, e = os.Stat(filepath.Join(c.Dir, "objects", "orphan.wdb")); !os.IsNotExist(e) {
		t.Fatal("orphan not pruned", e)
	}
	// A valid signature under a newly configured key cannot silently reset old trust/history.
	otherPub, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	signed, _ := snapshot.Sign(m, otherKey)
	os.WriteFile(filepath.Join(public, "manifest.json"), signed, 0644)
	c.TrustedKey = otherPub
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("key change silently reset history")
	}
}

func TestImmutableMirrorBaseAndUnapprovedHost(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	public := filepath.Join(dir, "public")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /latest/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(public, "manifest.json"))
	})
	mux.HandleFunc("GET /release/tag/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !snapshot.ArtifactName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(public, name))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	s := makeCatalog(t, filepath.Join(dir, "data"), "1")
	m, e := exporter.Export(ctx, public, s, key, srv.URL+"/release/tag/", time.Hour, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c := Client{URL: srv.URL + "/latest/manifest.json", Dir: filepath.Join(dir, "agent"), HTTP: srv.Client(), TrustedKey: pub}
	r, e := c.Update(ctx)
	if e != nil || r.Downloaded != 2 {
		t.Fatal(r, e)
	}
	before, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	m.Revision++
	m.BaseURL = "https://unapproved.invalid/release/"
	raw, _ := snapshot.Sign(m, key)
	os.WriteFile(filepath.Join(public, "manifest.json"), raw, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("unknown artifact host accepted")
	}
	after, _ := os.ReadFile(filepath.Join(c.Dir, "current.json"))
	if string(before) != string(after) {
		t.Fatal("changed checkpoint on rejected mirror")
	}
}

func TestPollConditionalAndIncremental(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	public := filepath.Join(dir, "public")
	now := time.Now().UTC()
	first := makeCatalog(t, filepath.Join(dir, "first"), "1")
	if _, err := exporter.Export(ctx, public, first, key, "", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	var objects, notModified atomic.Int32
	var legacy atomic.Bool
	handler := publish.Artifacts(public)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/manifest.json" {
			objects.Add(1)
			handler.ServeHTTP(w, r)
			return
		}
		if legacy.Load() {
			r.Header.Del("If-None-Match")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code == http.StatusNotModified {
			notModified.Add(1)
			if rec.Body.Len() != 0 {
				t.Error("304 carried a manifest body")
			}
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer srv.Close()
	c := Client{URL: srv.URL + "/v1/manifest.json", Dir: filepath.Join(dir, "agent"), HTTP: srv.Client(), TrustedKey: pub}
	r, e := c.Poll(ctx)
	if e != nil || !r.Changed || r.Downloaded != 2 {
		t.Fatal(r, e)
	}
	checkpoint := filepath.Join(c.Dir, "current.json")
	stamp := now.Add(-time.Hour)
	if e = os.Chtimes(checkpoint, stamp, stamp); e != nil {
		t.Fatal(e)
	}
	objects.Store(0)
	r, e = c.Poll(ctx)
	if e != nil || r.Changed || objects.Load() != 0 || notModified.Load() != 1 {
		t.Fatal(r, e, objects.Load(), notModified.Load())
	}
	legacy.Store(true)
	r, e = c.Poll(ctx)
	if e != nil || r.Changed || objects.Load() != 0 {
		t.Fatal(r, e)
	}
	info, e := os.Stat(checkpoint)
	if e != nil || info.ModTime().Unix() != stamp.Unix() {
		t.Fatal("unchanged polling rewrote checkpoint", e)
	}
	legacy.Store(false)
	renewed, e := exporter.Export(ctx, public, first, key, "", time.Hour, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
	}
	r, e = c.Poll(ctx)
	if e != nil || r.Changed || r.Revision != renewed.Revision || objects.Load() != 0 {
		t.Fatal(r, e)
	}
	second := makeCatalog(t, filepath.Join(dir, "second"), "2")
	if _, e = exporter.Export(ctx, public, second, key, "", time.Hour, now.Add(2*time.Second)); e != nil {
		t.Fatal(e)
	}
	r, e = c.Poll(ctx)
	if e != nil || !r.Changed || r.Downloaded != 1 || objects.Load() != 1 {
		t.Fatal(r, e)
	}
	c.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, e = c.Poll(ctx); e == nil {
		t.Fatal("expired publication accepted by polling")
	}
}
