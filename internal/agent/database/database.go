// Package database installs signed disk snapshots without materializing a feed.
package database

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/filelock"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/snapshot"
	"time"
)

type Client struct {
	URL, Dir     string
	HTTP         *http.Client
	TrustedKey   ed25519.PublicKey
	AllowedHosts []string
	Now          func() time.Time
}
type Result struct {
	Revision      int64             `json:"revision"`
	Objects       int               `json:"objects"`
	Downloaded    int               `json:"downloaded"`
	WireBytes     int64             `json:"wire_bytes"`
	DatabaseBytes int64             `json:"database_bytes"`
	Profile       compactdb.Profile `json:"profile"`
}
type pointer struct {
	Envelope []byte `json:"envelope"`
	Key      []byte `json:"key"`
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}
func current(dir string, key ed25519.PublicKey, fresh bool, now time.Time) (pointer, snapshot.Manifest, error) {
	var p pointer
	var m snapshot.Manifest
	e := atomicfile.ReadJSON(filepath.Join(dir, "current.json"), &p, 2*snapshot.MaxManifest)
	if e != nil {
		return p, m, e
	}
	if len(key) > 0 && !bytes.Equal(key, p.Key) {
		return p, m, errors.New("installed snapshot uses a different trusted key")
	}
	check := now
	if !fresh {
		var env snapshot.Envelope
		json.Unmarshal(p.Envelope, &env)
		var previous snapshot.Manifest
		json.Unmarshal(env.Payload, &previous)
		check = previous.CreatedAt
	}
	m, e = snapshot.Verify(p.Envelope, ed25519.PublicKey(p.Key), check)
	return p, m, e
}
func (c *Client) Update(ctx context.Context) (Result, error) {
	var result Result
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	if len(c.TrustedKey) != ed25519.PublicKeySize {
		return result, errors.New("trusted Ed25519 key required")
	}
	if c.Dir == "" {
		return result, errors.New("database directory required")
	}
	unlock, e := filelock.Acquire(ctx, filepath.Join(c.Dir, "update.lock"), false)
	if e != nil {
		return result, e
	}
	defer unlock()
	u, e := url.Parse(c.URL)
	if e != nil {
		return result, e
	}
	hosts := append([]string{u.Hostname()}, c.AllowedHosts...)
	if e = netpolicy.URL(c.URL, hosts); e != nil {
		return result, e
	}
	h := c.HTTP
	if h == nil {
		h, e = netpolicy.Client("", hosts)
		if e != nil {
			return result, e
		}
	}
	hc := *h
	hc.Timeout = 20 * time.Minute
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return netpolicy.URL(r.URL.String(), hosts)
	}
	defer hc.CloseIdleConnections()
	resp, e := request(ctx, &hc, c.URL, snapshot.MaxManifest)
	if e != nil {
		return result, e
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, snapshot.MaxManifest+1))
	resp.Body.Close()
	if e != nil {
		return result, e
	}
	m, e := snapshot.Verify(raw, c.TrustedKey, c.now())
	if e != nil {
		return result, e
	}
	old, previous, e := current(c.Dir, c.TrustedKey, false, c.now())
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if m.Revision < previous.Revision || (m.Revision == previous.Revision && snapshot.PayloadDigest(old.Envelope) != snapshot.PayloadDigest(raw)) {
		return result, errors.New("rollback or conflicting snapshot revision rejected")
	}
	if previous.Profile != "" && previous.Profile != m.Profile {
		return result, errors.New("publication profile changed; use a separate state directory")
	}
	base := u
	if m.BaseURL != "" {
		base, e = url.Parse(m.BaseURL)
		if e != nil || base.RawQuery != "" || len(base.Path) == 0 || base.Path[len(base.Path)-1] != '/' {
			return result, errors.New("invalid artifact base directory")
		}
		if e = netpolicy.URL(base.String(), hosts); e != nil {
			return result, e
		}
	}
	objects := filepath.Join(c.Dir, "objects")
	if e = os.MkdirAll(objects, 0700); e != nil {
		return result, e
	}
	// Bound interrupted-update storage to the installed and currently targeted snapshots.
	guard, err := filelock.Acquire(ctx, filepath.Join(c.Dir, "active.lock"), false)
	if err != nil {
		return result, err
	}
	e = prune(objects, previous.Objects, m.Objects)
	guard()
	if e != nil {
		return result, e
	}
	for _, obj := range m.Objects {
		result.DatabaseBytes += obj.Bytes
		dest := filepath.Join(objects, obj.SHA256+".wdb")
		if st, err := os.Stat(dest); err == nil && st.Size() == obj.Bytes {
			f, err := compactdb.Open(dest)
			if err == nil {
				f.Close()
				continue
			}
		}
		target := base.ResolveReference(&url.URL{Path: obj.Name()}).String()
		if e = netpolicy.URL(target, hosts); e != nil {
			return result, e
		}
		if e = install(ctx, &hc, target, dest, obj); e != nil {
			return result, fmt.Errorf("object %s: %w", obj.Slot, e)
		}
		result.Downloaded++
		result.WireBytes += obj.Bytes
	}
	// Persist object-directory renames before persisting a pointer to those files.
	disk, e := os.Open(objects)
	if e != nil {
		return result, e
	}
	e = disk.Sync()
	disk.Close()
	if e != nil {
		return result, e
	}
	if _, e = snapshot.Verify(raw, c.TrustedKey, c.now()); e != nil {
		return result, e
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	active, e := filelock.Acquire(ctx, filepath.Join(c.Dir, "active.lock"), false)
	if e != nil {
		return result, e
	}
	defer active()
	if e = atomicfile.JSON(filepath.Join(c.Dir, "current.json"), pointer{raw, c.TrustedKey}); e != nil {
		return result, e
	}
	// Readers hold active.lock shared; obsolete objects can now be removed safely.
	_ = prune(objects, m.Objects, nil)

	result.Revision = m.Revision
	result.Objects = len(m.Objects)
	result.Profile = m.Profile
	return result, nil
}
func request(ctx context.Context, h *http.Client, target string, max int64) (*http.Response, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := h.Do(req)
	if e != nil {
		return nil, errors.New("snapshot HTTPS request failed")
	}
	if resp.StatusCode != 200 || resp.ContentLength > max {
		resp.Body.Close()
		return nil, errors.New("snapshot status/size rejected")
	}
	return resp, nil
}
func install(ctx context.Context, h *http.Client, target, dest string, o snapshot.Object) error {
	resp, e := request(ctx, h, target, o.Bytes)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	temp, e := os.CreateTemp(filepath.Dir(dest), "download-*")
	if e != nil {
		return e
	}
	defer temp.Close()
	defer os.Remove(temp.Name())
	digest := sha256.New()
	n, e := io.CopyBuffer(io.MultiWriter(temp, digest), io.LimitReader(resp.Body, o.Bytes+1), make([]byte, 32<<10))
	if e != nil {
		return e
	}
	if n != o.Bytes || hex.EncodeToString(digest.Sum(nil)) != o.SHA256 {
		return errors.New("object size/digest mismatch")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = temp.Sync(); e != nil {
		return e
	}
	if e = temp.Close(); e != nil {
		return e
	}
	f, e := compactdb.Open(temp.Name())
	if e != nil {
		return e
	}
	if int64(f.Rows) != o.Rows {
		f.Close()
		return errors.New("row count mismatch")
	}
	e = f.Validate(ctx)
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(temp.Name(), dest)
}

// Lookup is entirely local. Emit one row at a time with an explicit result bound.
func Lookup(ctx context.Context, dir, group, key string, limit int, emit func([]byte) error) error {
	if group != "p" && group != "v" && group != "r" && group != "s" {
		return errors.New("invalid lookup group")
	}
	if limit < 1 || limit > 10000 {
		return errors.New("lookup limit must be 1..10000")
	}
	unlock, e := filelock.Acquire(ctx, filepath.Join(dir, "active.lock"), true)
	if e != nil {
		return e
	}
	defer unlock()
	_, m, e := current(dir, nil, true, time.Now())
	if e != nil {
		return e
	}
	slot := compactdb.Slot(group, key)
	for _, o := range m.Objects {
		if o.Slot != slot {
			continue
		}
		f, e := compactdb.Open(filepath.Join(dir, "objects", o.SHA256+".wdb"))
		if e != nil {
			return e
		}
		defer f.Close()
		n := 0
		return f.Find(ctx, compactdb.KeyHash(group, key), func(v []byte) error {
			n++
			if n > limit {
				return errors.New("result limit reached; query is incomplete")
			}
			return emit(v)
		})
	}
	return nil
}

func (c *Client) Refresh(ctx context.Context) error { _, e := c.Update(ctx); return e }

func prune(dir string, installed, target []snapshot.Object) error {
	keep := make(map[string]bool, len(installed)+len(target))
	for _, list := range [][]snapshot.Object{installed, target} {
		for _, o := range list {
			keep[o.SHA256+".wdb"] = true
		}
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, ent := range entries {
		if !ent.IsDir() && !keep[ent.Name()] {
			if e = os.Remove(filepath.Join(dir, ent.Name())); e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
	}
	return nil
}
