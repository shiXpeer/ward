package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"testing"
	"time"

	"shixpeer.com/ward/pkg/inventory"
)

func TestRunCollectsAndPullsUntilCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &memStore{}
	collected := make(chan struct{})
	pulled := make(chan struct{})
	a := &Agent{
		Collector: collectorFunc(func(ctx context.Context) (inventory.Snapshot, error) {
			closeOnce(collected)
			return sampleSnapshot(), nil
		}),
		Updater: updateFunc(func(ctx context.Context) error {
			store.mu.Lock()
			store.feeds++
			store.mu.Unlock()
			closeOnce(pulled)
			return nil
		}),
		Store:           store,
		CollectInterval: time.Hour,
		FeedInterval:    time.Hour,
		Log:             log.New(io.Discard, "", 0),
	}
	errc := make(chan error, 1)
	go func() { errc <- a.Run(ctx) }()
	wait(t, collected, "collect")
	wait(t, pulled, "pull")
	cancel()
	if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.snaps != 1 || store.feeds != 1 {
		t.Fatalf("snaps=%d feeds=%d", store.snaps, store.feeds)
	}
}

func TestRunPullsWhileCollectBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &memStore{}
	pulled := make(chan struct{})
	a := &Agent{
		Collector: collectorFunc(func(ctx context.Context) (inventory.Snapshot, error) {
			<-ctx.Done()
			return inventory.Snapshot{}, ctx.Err()
		}),
		Updater: updateFunc(func(ctx context.Context) error {
			store.mu.Lock()
			store.feeds++
			store.mu.Unlock()
			closeOnce(pulled)
			return nil
		}),
		Store:           store,
		CollectInterval: time.Hour,
		FeedInterval:    time.Hour,
		Log:             log.New(io.Discard, "", 0),
	}
	errc := make(chan error, 1)
	go func() { errc <- a.Run(ctx) }()
	wait(t, pulled, "pull")
	cancel()
	if err := waitErr(t, errc); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.snaps != 0 || store.feeds != 1 {
		t.Fatalf("snaps=%d feeds=%d", store.snaps, store.feeds)
	}
}

func TestRunRejectsShortInterval(t *testing.T) {
	a := &Agent{
		Collector: collectorFunc(func(context.Context) (inventory.Snapshot, error) {
			return inventory.Snapshot{}, errors.New("unused")
		}),
		Store:           &memStore{},
		CollectInterval: 0,
	}
	if err := a.Run(context.Background()); err == nil {
		t.Fatal("expected interval error")
	}
}

type collectorFunc func(context.Context) (inventory.Snapshot, error)

func (f collectorFunc) Snapshot(ctx context.Context) (inventory.Snapshot, error) {
	return f(ctx)
}

type updateFunc func(context.Context) error

func (f updateFunc) Refresh(ctx context.Context) error { return f(ctx) }

type memStore struct {
	mu    sync.Mutex
	snaps int
	feeds int
}

func (m *memStore) SaveSnapshot(ctx context.Context, snap inventory.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snaps++
	return nil
}

func sampleSnapshot() inventory.Snapshot {
	return inventory.Snapshot{
		FormatVersion:    inventory.FormatVersion,
		Collector:        "hostagent",
		CollectorVersion: "0.1.0",
		CollectedAt:      time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
		Coverage:         []inventory.Note{},
	}
}

func closeOnce(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func wait(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitErr(t *testing.T, errc <-chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("agent did not stop")
		return nil
	}
}
