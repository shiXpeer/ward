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
	if e != nil || result.Downloaded != 2 {
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
	if e != nil || result.Downloaded != 0 || requests.Load() != 0 {
		t.Fatal(result, e, requests.Load())
	}
	second := makeCatalog(t, filepath.Join(dir, "second"), "2")
	m2, e := exporter.Export(ctx, public, second, key, "", time.Hour, now.Add(time.Second))
	if e != nil {
		t.Fatal(e)
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
	result, e = c.Update(ctx)
	if e != nil || result.Downloaded != 1 || requests.Load() != 1 {
		t.Fatal(result, e, requests.Load())
	}
	old, _ := snapshot.Sign(m, key)
	atomicfile.Write(filepath.Join(public, "manifest.json"), old, 0644)
	if _, e = c.Update(ctx); e == nil {
		t.Fatal("rollback accepted")
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
