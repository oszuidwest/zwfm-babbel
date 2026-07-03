package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// runner executes a job immediately on Start and then at a fixed interval in a
// background goroutine until Stop is called. Each run receives a context that
// is cancelled after runTimeout.
type runner struct {
	name       string
	interval   time.Duration
	runTimeout time.Duration
	fn         func(ctx context.Context)

	ticker *time.Ticker
	done   chan bool
	// stopOnce prevents double-stop race conditions when Stop is called more
	// than once.
	stopOnce sync.Once
}

// newRunner returns a stopped runner that executes fn every interval.
func newRunner(name string, interval, runTimeout time.Duration, fn func(ctx context.Context)) *runner {
	return &runner{
		name:       name,
		interval:   interval,
		runTimeout: runTimeout,
		fn:         fn,
		done:       make(chan bool),
	}
}

// Start runs the job immediately and then every interval in a background
// goroutine.
func (r *runner) Start() {
	r.runOnce()

	r.ticker = time.NewTicker(r.interval)

	go func() {
		for {
			select {
			case <-r.ticker.C:
				r.runOnce()
			case <-r.done:
				return
			}
		}
	}()
}

// runOnce executes the job with a per-run timeout context.
func (r *runner) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), r.runTimeout)
	defer cancel()
	r.fn(ctx)
}

// Stop gracefully shuts down the runner.
// Uses sync.Once to prevent double-stop race conditions and a timeout to prevent deadlock.
// Sends the done signal before stopping the ticker to avoid a race condition where the
// goroutine might read from a closed ticker channel before receiving the shutdown signal.
func (r *runner) Stop() {
	r.stopOnce.Do(func() {
		logger.Info("Stopping " + r.name)
		// Signal done FIRST to ensure the goroutine exits before we stop the
		// ticker. This prevents a race condition where ticker.C could be read
		// after Stop().
		select {
		case r.done <- true:
		case <-time.After(5 * time.Second):
			logger.Info("Shutdown timeout", "service", r.name)
		}
		if r.ticker != nil {
			r.ticker.Stop()
		}
	})
}
