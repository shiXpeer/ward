// Package exporter writes immutable disk artifacts with internally compressed blocks and publishes the signed root last.
package exporter

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/beacon/catalog"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/filelock"
	"shixpeer.com/ward/internal/snapshot"
	"time"
)

func Export(ctx context.Context, dir string, s catalog.Summary, key ed25519.PrivateKey, base string, ttl time.Duration, now time.Time) (snapshot.Manifest, error) {
	var m snapshot.Manifest
	if len(key) != ed25519.PrivateKeySize {
		return m, errors.New("invalid signing key")
	}
	if ttl <= 0 || ttl > 7*24*time.Hour {
		return m, errors.New("TTL must be positive and at most 7 days")
	}
	if e := os.MkdirAll(dir, 0755); e != nil {
		return m, e
	}
	unlock, e := filelock.Acquire(ctx, filepath.Join(dir, ".export.lock"), false)
	if e != nil {
		return m, e
	}
	defer unlock()
	m = snapshot.Manifest{Version: snapshot.Version, Format: compactdb.Format, Revision: now.UnixNano(), CreatedAt: now.UTC(), ExpiresAt: now.Add(ttl).UTC(), BaseURL: base, Profile: s.Profile, Generation: s.Generation, Sources: s.Sources}
	var old snapshot.Manifest
	if b, e := os.ReadFile(filepath.Join(dir, "manifest.json")); e == nil {
		old, _ = snapshot.Verify(b, key.Public().(ed25519.PublicKey), now)
		if m.Revision <= old.Revision {
			m.Revision = old.Revision + 1
		}
	}
	for _, b := range s.Buckets {
		if e = ctx.Err(); e != nil {
			return m, e
		}
		// Fingerprint the disk file with a fixed buffer. Reuse its immutable wire object.
		h := sha256.New()
		f, e := os.Open(b.Path)
		if e != nil {
			return m, e
		}
		n, e := io.Copy(h, f)
		f.Close()
		if e != nil {
			return m, e
		}
		sum := hex.EncodeToString(h.Sum(nil))
		var obj snapshot.Object
		for _, o := range old.Objects {
			if o.Slot == b.Slot && o.SHA256 == sum {
				if st, e := os.Stat(filepath.Join(dir, o.Name())); e == nil && st.Size() == o.Bytes {
					obj = o
					break
				}
			}
		}
		if obj.SHA256 == "" {
			obj, e = copyObject(ctx, dir, b, sum, n)
			if e != nil {
				return m, e
			}
		}
		m.Objects = append(m.Objects, obj)
	}
	raw, e := snapshot.Sign(m, key)
	if e != nil {
		return m, e
	}
	if _, e = snapshot.Verify(raw, key.Public().(ed25519.PublicKey), now); e != nil {
		return m, e
	}
	return m, atomicfile.Write(filepath.Join(dir, "manifest.json"), raw, 0644)
}
func copyObject(ctx context.Context, dir string, b compactdb.Bucket, sum string, n int64) (snapshot.Object, error) {
	obj := snapshot.Object{Slot: b.Slot, SHA256: sum, Bytes: n, Rows: b.Rows}
	if n > snapshot.MaxObject {
		return obj, fmt.Errorf("bucket %s exceeds object bound", b.Slot)
	}
	f, e := os.Open(b.Path)
	if e != nil {
		return obj, e
	}
	defer f.Close()
	temp, e := os.CreateTemp(dir, ".object-*")
	if e != nil {
		return obj, e
	}
	defer temp.Close()
	defer os.Remove(temp.Name())
	h := sha256.New()
	copied, e := io.CopyBuffer(io.MultiWriter(temp, h), &contextReader{ctx, f}, make([]byte, 32<<10))
	if e != nil {
		return obj, e
	}
	if copied != n || hex.EncodeToString(h.Sum(nil)) != sum {
		return obj, errors.New("catalog changed during export")
	}
	if e = temp.Chmod(0644); e != nil {
		return obj, e
	}
	if e = temp.Sync(); e != nil {
		return obj, e
	}
	if e = temp.Close(); e != nil {
		return obj, e
	}
	return obj, os.Rename(temp.Name(), filepath.Join(dir, obj.Name()))
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(b)
}
