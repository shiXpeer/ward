// Package state stores private local host inventory; database files are separate.
package state

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/atomicfile"

	"shixpeer.com/ward/pkg/inventory"
)

const (
	SnapshotFile = "snapshot.json"
)

type File struct {
	dir string
}

func Open(dir string) (*File, error) {
	if dir == "" {
		return nil, errors.New("state: directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &File{dir: dir}, nil
}

func (f *File) SaveSnapshot(ctx context.Context, snap inventory.Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeJSON(filepath.Join(f.dir, SnapshotFile), snap)
}

func (f *File) LoadSnapshot(ctx context.Context) (inventory.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return inventory.Snapshot{}, err
	}
	var snap inventory.Snapshot
	if err := readJSON(filepath.Join(f.dir, SnapshotFile), &snap); err != nil {
		return inventory.Snapshot{}, err
	}
	return snap, nil
}

func writeJSON(path string, value any) error { return atomicfile.JSON(path, value) }

func readJSON(path string, dest any) error {
	if err := atomicfile.ReadJSON(path, dest, 16<<20); err != nil {
		return fmt.Errorf("state: %s: %w", filepath.Base(path), err)
	}
	return nil
}
