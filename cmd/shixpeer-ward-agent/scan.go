package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	return runScanWithProgress(ctx, dir, dest, key, collect, output, progress, nil)
}

type scanProgress struct {
	Stage     string `json:"stage"`
	Component string `json:"component,omitempty"`
	Done      int    `json:"done"`
	Total     int    `json:"total"`
	Matches   int    `json:"matches"`
	Review    int    `json:"review"`
	Seconds   int    `json:"seconds,omitempty"`
}

func runScanWithProgress(ctx context.Context, dir, dest string, key ed25519.PublicKey, collect func(context.Context) (inventory.Snapshot, error), output, progress io.Writer, events *json.Encoder) error {
	emit := func(event scanProgress) {
		if events != nil {
			_ = events.Encode(event)
		}
	}
	emit(scanProgress{Stage: "inventory"})
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
	if hostname, err := os.Hostname(); err == nil {
		hostname = strings.TrimSpace(hostname)
		if len(hostname) <= 255 && !strings.ContainsAny(hostname, "\r\n\x00") {
			report.Hostname = hostname
		}
	}
	emit(scanProgress{Stage: "database"})
	db, scanErr := database.OpenReader(ctx, filepath.Join(dir, "database"), key)
	if scanErr == nil {
		var notify func(int, int, int, int, string)
		if events != nil {
			start := time.Now()
			last := time.Time{}
			notify = func(done, total, matches, review int, component string) {
				now := time.Now()
				if now.Sub(last) < 120*time.Millisecond {
					return
				}
				last = now
				event := scanProgress{Stage: "matching", Done: done, Total: total, Matches: matches, Review: review, Component: component}
				if done >= 10 {
					event.Seconds = 1 + int(now.Sub(start).Seconds()*float64(total-done)/float64(done))
				}
				emit(event)
			}
		}
		scanErr = scan.RunWithProgress(ctx, &report, db, notify)
		db.Close()
	}
	if scanErr != nil {
		report.Coverage = append(report.Coverage, inventory.Note{Code: inventory.Unavailable, Source: "database-scan", Detail: scanErr.Error()})
		report.Status = "incomplete"
	}
	if dest == "" {
		dest = dir
	}
	emit(scanProgress{Stage: "report", Matches: report.Confirmed, Review: report.Review})
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
