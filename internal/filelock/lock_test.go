package filelock

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSharedReadersAndCancelledWriter(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lock")
	a, e := Acquire(context.Background(), p, true)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Acquire(context.Background(), p, true)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, e = Acquire(ctx, p, false); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("writer acquired while readers live", e)
	}
	a()
	b()
	unlock, e := Acquire(context.Background(), p, false)
	if e != nil {
		t.Fatal(e)
	}
	unlock()
}
