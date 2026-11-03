package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestResidentUpdatesBeforeFirstScanAndSurvivesErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var updates, scans atomic.Int32
	update := func(context.Context) error { updates.Add(1); return errors.New("fixture update failure") }
	scan := func(context.Context) error {
		if updates.Load() < 1 {
			t.Error("scan preceded initial update")
		}
		if scans.Add(1) == 2 {
			cancel()
		}
		return errors.New("fixture scan failure")
	}
	err := Resident(ctx, update, scan, time.Hour, time.Second, log.New(io.Discard, "", 0))
	if !errors.Is(err, context.Canceled) || scans.Load() != 2 {
		t.Fatal(err, scans.Load())
	}
}
func TestResidentRejectsInvalidIntervals(t *testing.T) {
	if err := Resident(context.Background(), nil, func(context.Context) error { return nil }, time.Hour, 0, nil); err == nil {
		t.Fatal("invalid interval accepted")
	}
}

func TestResidentLogIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "agent.log")
	l, err := OpenLog(path, 8)
	if err != nil {
		t.Fatal(err)
	}
	l.Write([]byte("12345678"))
	l.Write([]byte("abcd"))
	l.Write([]byte("efgh"))
	l.Write([]byte("next"))
	l.Close()
	for _, name := range []string{path, path + ".previous"} {
		st, err := os.Stat(name)
		if err != nil || st.Size() > 8 || st.Mode().Perm() != 0600 {
			t.Fatal(st, err)
		}
	}
}

func TestSuccessfulBackgroundUpdateRequestsReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var scans atomic.Int32
	err := Resident(ctx, func(context.Context) error { return nil }, func(context.Context) error {
		if scans.Add(1) == 2 {
			cancel()
		}
		return nil
	}, time.Second, time.Hour, log.New(io.Discard, "", 0))
	if !errors.Is(err, context.Canceled) || scans.Load() != 2 {
		t.Fatal(err, scans.Load())
	}
}
