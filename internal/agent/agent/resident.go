package agent

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// Resident updates the shared database and repeatedly produces full local scan
// reports. Startup update precedes the first scan; later loops are independent.
// Failed downloads retry within a minute; successful updates request a new scan.
func Resident(ctx context.Context, update, scan func(context.Context) error, updateEvery, scanEvery time.Duration, logger *log.Logger) error {
	if scan == nil || scanEvery < time.Second || update != nil && updateEvery < time.Second {
		return errors.New("resident: tasks/intervals invalid")
	}
	if logger == nil {
		logger = log.Default()
	}
	invoke := func(name string, fn func(context.Context) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		logger.Printf("%s: starting", name)
		err := fn(ctx)
		if err != nil && ctx.Err() == nil {
			logger.Printf("%s: %v", name, err)
		} else if err == nil {
			logger.Printf("%s: complete", name)
		}
		return err
	}
	var initialErr error
	if update != nil {
		initialErr = invoke("database", update)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	requests := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		invoke("scan", scan)
		timer := time.NewTimer(scanEvery)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-requests:
				invoke("scan", scan)
				timer.Reset(scanEvery)
			case <-timer.C:
				invoke("scan", scan)
				timer.Reset(scanEvery)
			}
		}
	}()
	if update != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			delay := updateEvery
			if initialErr != nil {
				delay = min(updateEvery, time.Minute)
			}
			timer := time.NewTimer(delay)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					err := invoke("database", update)
					delay = updateEvery
					if err != nil {
						delay = min(updateEvery, time.Minute)
					} else {
						select {
						case requests <- struct{}{}:
						default:
						}
					}
					timer.Reset(delay)
				}
			}
		}()
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}
