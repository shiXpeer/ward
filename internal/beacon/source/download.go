package source

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

type downloadKey struct{}
type downloadBudget struct {
	slots   chan struct{}
	stripes [64]chan struct{}
	pins    string
}

// WithDownloadBudget limits HTTP work across adapters, including nested NVD
// workers. Pins preserve the exact prepared bytes until normalization completes.
func WithDownloadBudget(ctx context.Context, workers int, pins string) context.Context {
	b := &downloadBudget{slots: make(chan struct{}, workers), pins: pins}
	for i := range b.stripes {
		b.stripes[i] = make(chan struct{}, 1)
	}
	return context.WithValue(ctx, downloadKey{}, b)
}
func (b *downloadBudget) acquire(ctx context.Context, key byte) (func(), error) {
	stripe := b.stripes[int(key)%len(b.stripes)]
	select {
	case stripe <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case b.slots <- struct{}{}:
		return func() { <-b.slots; <-stripe }, nil
	case <-ctx.Done():
		<-stripe
		return nil, ctx.Err()
	}
}
func (b *downloadBudget) pin(path, id, digest string) (Input, error) {
	if len(digest) != 64 {
		return Input{}, errors.New("invalid cached body digest")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return Input{}, err
	}
	dest := filepath.Join(b.pins, id+"-"+digest+".body")
	if err := os.Link(path, dest); err != nil && !errors.Is(err, os.ErrExist) {
		return Input{}, err
	}
	return Input{Path: dest, Digest: digest, Dependencies: []string{path}}, nil
}
