package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/agent/scan"
	"shixpeer.com/ward/internal/agent/state"
	"shixpeer.com/ward/pkg/inventory"
)

func runScan(ctx context.Context, dir, dest string, key ed25519.PublicKey, collect func(context.Context) (inventory.Snapshot, error)) error {
	return runScanTo(ctx, dir, dest, key, collect, os.Stdout, os.Stderr)
}
func runScanTo(ctx context.Context, dir, dest string, key ed25519.PublicKey, collect func(context.Context) (inventory.Snapshot, error), output, progress io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	fmt.Fprintln(progress, "Collecting local installed versions; no downloads or software changes.")
	snap, err := collect(ctx)
	if err != nil {
		return err
	}
	if err = snap.Validate(); err != nil {
		return err
	}
	st, err := state.Open(dir)
	if err != nil {
		return err
	}
	if err = st.SaveSnapshot(ctx, snap); err != nil {
		return err
	}
	report := scan.New(snap)
	db, scanErr := database.OpenReader(ctx, filepath.Join(dir, "database"), key)
	if scanErr == nil {
		scanErr = scan.Run(ctx, &report, db)
		db.Close()
	}
	if scanErr != nil {
		report.Coverage = append(report.Coverage, inventory.Note{Code: inventory.Unavailable, Source: "database-scan", Detail: scanErr.Error()})
		report.Status = "incomplete"
	}
	if dest == "" {
		dest = dir
	}
	if err = scan.Save(dest, report); err != nil {
		return err
	}
	if err = scan.Console(output, report, filepath.Join(dest, "report.json"), filepath.Join(dest, "report.md")); err != nil {
		return err
	}
	if scanErr != nil {
		return fmt.Errorf("scan incomplete (report saved): %w; run update if the database is missing or expired", scanErr)
	}
	return nil
}
