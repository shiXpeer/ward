// Package agent is the resident loop: collect local state, and separately
// download the vulnerability feed. A failure in either pass is logged.
// The process keeps running until the context is cancelled.
package agent

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"shixpeer.com/ward/pkg/inventory"
)

type Collector interface {
	Snapshot(ctx context.Context) (inventory.Snapshot, error)
}

type Store interface {
	SaveSnapshot(ctx context.Context, snap inventory.Snapshot) error
}

type Updater interface{ Refresh(context.Context) error }

type Agent struct {
	Updater         Updater
	Collector       Collector
	Store           Store
	CollectInterval time.Duration
	FeedInterval    time.Duration
	Log             *log.Logger
}

func (a *Agent) Run(ctx context.Context) error {
	if a.Collector == nil || a.Store == nil {
		return errors.New("agent: collector and store are required")
	}
	if a.CollectInterval < time.Second {
		return errors.New("agent: collect interval must be at least 1s")
	}
	if a.Updater != nil && a.FeedInterval < time.Second {
		return errors.New("agent: feed interval must be at least 1s")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.every(ctx, a.CollectInterval, a.collect)
	}()
	if a.Updater != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.every(ctx, a.FeedInterval, a.pull)
		}()
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

func (a *Agent) every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	fn(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func (a *Agent) collect(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	snap, err := a.Collector.Snapshot(ctx)
	if err != nil {
		a.logger().Printf("collect: %v", err)
		return
	}
	if err := snap.Validate(); err != nil {
		a.logger().Printf("collect: %v", err)
		return
	}
	if err := a.Store.SaveSnapshot(ctx, snap); err != nil {
		a.logger().Printf("collect: %v", err)
	}
}

func (a *Agent) pull(ctx context.Context) {
	if a.Updater == nil || ctx.Err() != nil {
		return
	}
	if e := a.Updater.Refresh(ctx); e != nil {
		a.logger().Printf("database: %v", e)
	}
}

func (a *Agent) logger() *log.Logger {
	if a.Log != nil {
		return a.Log
	}
	return log.Default()
}
