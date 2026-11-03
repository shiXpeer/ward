package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/filelock"
	"shixpeer.com/ward/internal/paths"
)

func migrateHome(args []string) error {
	fs := flag.NewFlagSet("migrate-home", flag.ContinueOnError)
	from := fs.String("from-config", paths.LegacyConfig(), "old agent settings to copy; source is retained as a backup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected migration arguments")
	}
	if paths.Root() == "" {
		return errors.New("absolute HOME required")
	}
	if _, err := os.Stat(paths.Config("agent")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("home settings already exist; refusing to replace trust/checkpoint")
	}
	s, err := loadSettings(*from)
	if err != nil {
		return err
	}
	if s.URL == "" {
		return errors.New("legacy settings not found")
	}
	if _, err = os.Stat(paths.State("agent")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("target agent directory already exists or cannot be inspected")
	}
	if err = os.MkdirAll(paths.Root(), 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	updateUnlock, err := filelock.Acquire(ctx, filepath.Join(s.State, "database", "update.lock"), false)
	if err != nil {
		return err
	}
	defer updateUnlock()
	activeUnlock, err := filelock.Acquire(ctx, filepath.Join(s.State, "database", "active.lock"), true)
	if err != nil {
		return err
	}
	defer activeUnlock()
	stage, err := os.MkdirTemp(paths.Root(), "migration-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	var total int64
	files := 0
	err = filepath.WalkDir(s.State, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(s.State, path)
		if e != nil {
			return e
		}
		dest := filepath.Join(stage, "agent", rel)
		if d.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		st, e := d.Info()
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("migration refuses special file/symlink: %s", rel)
		}
		files++
		total += st.Size()
		if files > 10000 || total > 5<<30 {
			return errors.New("migration exceeds file/size budget")
		}
		input, e := os.Open(path)
		if e != nil {
			return e
		}
		defer input.Close()
		return atomicfile.Stream(dest, func(w io.Writer) error { _, e := io.Copy(w, input); return e })
	})
	if err != nil {
		return err
	}
	if s.CA != "" {
		raw, e := os.ReadFile(s.CA)
		if e != nil {
			return e
		}
		if len(raw) > 1<<20 {
			return errors.New("CA exceeds limit")
		}
		s.CA = filepath.Join(paths.Root(), "config", "agent-ca.crt")
		if e = atomicfile.Write(s.CA, raw, 0600); e != nil {
			return e
		}
	}
	if err = os.Rename(filepath.Join(stage, "agent"), paths.State("agent")); err != nil {
		return err
	}
	s.State = paths.State("agent")
	if err = atomicfile.JSON(paths.Config("agent"), s); err != nil {
		return err
	}
	fmt.Println("Migrated settings, database checkpoint and reports to", paths.Root())
	fmt.Println("Legacy files remain as a backup; remove them only after checking update/scan.")
	return nil
}
