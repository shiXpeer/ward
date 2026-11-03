package database

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"time"

	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/filelock"
	"shixpeer.com/ward/internal/snapshot"
)

// Reader holds one authenticated publication and a shared generation lock for an
// entire offline scan. It opens one indexed object per query, never the full DB.
type Reader struct {
	dir      string
	Manifest snapshot.Manifest
	objects  map[string]snapshot.Object
	unlock   func()
}

func OpenReader(ctx context.Context, dir string, key ed25519.PublicKey) (*Reader, error) {
	unlock, err := filelock.Acquire(ctx, filepath.Join(dir, "active.lock"), true)
	if err != nil {
		return nil, err
	}
	_, m, err := current(dir, key, true, time.Now())
	if err != nil {
		unlock()
		return nil, err
	}
	r := &Reader{dir: dir, Manifest: m, objects: map[string]snapshot.Object{}, unlock: unlock}
	for _, o := range m.Objects {
		r.objects[o.Slot] = o
	}
	return r, nil
}
func (r *Reader) Close() {
	if r.unlock != nil {
		r.unlock()
		r.unlock = nil
	}
}
func (r *Reader) Lookup(ctx context.Context, group, key string, limit int, emit func([]byte) error) error {
	if r.unlock == nil {
		return errors.New("database reader closed")
	}
	if group != "p" && group != "v" && group != "r" && group != "s" {
		return errors.New("invalid lookup group")
	}
	if limit < 1 || limit > 100000 {
		return errors.New("reader lookup limit must be 1..100000")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	o, ok := r.objects[compactdb.Slot(group, key)]
	if !ok {
		return nil
	}
	f, err := compactdb.Open(filepath.Join(r.dir, "objects", o.SHA256+".wdb"))
	if err != nil {
		return err
	}
	defer f.Close()
	n := 0
	return f.Find(ctx, compactdb.KeyHash(group, key), func(b []byte) error {
		n++
		if n > limit {
			return errors.New("result limit reached; query is incomplete")
		}
		return emit(b)
	})
}
