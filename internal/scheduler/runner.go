package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// runner executes a job immediately on Start and then at a fixed interval in a
// background goroutine until Stop is called. Each run receives a context that
// is cancelled after runTimeout. A run that returns an error or panics raises
// an operational alert; a successful run resolves it.
type runner struct {
	name       string
	interval   time.Duration
	runTimeout time.Duration
	fn         func(ctx context.Context) error
	alerts     notify.Alerter

	ticker *time.Ticker
	done   chan bool
	// stopOnce prevents double-stop race conditions when Stop is called more
	// than once.
	stopOnce sync.Once
}

// newRunner returns a stopped runner that executes fn every interval.
// alerts must be non-nil; pass notify.Discard when notifications are absent.
func newRunner(name string, interval, runTimeout time.Duration, fn func(ctx context.Context) error, alerts notify.Alerter) *runner {
	return &runner{
		name:       name,
		interval:   interval,
		runTimeout: runTimeout,
		fn:         fn,
		alerts:     alerts,
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

// runOnce executes the job with a per-run timeout context and maintains the
// job's shared failure/recovery alert state.
func (r *runner) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), r.runTimeout)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("Scheduler job panicked", "service", r.name, "panic", recovered)
			r.alerts.Alert(ctx, notify.Event{
				Key: "scheduler:panic:" + r.name, Summary: "Scheduler job panicked: " + r.name,
				Details: fmt.Sprint(recovered), Kind: notify.KindImmediate,
			})
		}
	}()
	if err := r.fn(ctx); err != nil {
		r.alerts.Alert(ctx, notify.Event{
			Key: "scheduler:" + r.name, Summary: "Scheduler job repeatedly fails: " + r.name,
			Details: err.Error(), Kind: notify.KindContinuous,
		})
		return
	}
	r.alerts.Resolve(ctx, "scheduler:"+r.name,
		"Scheduler job recovered: "+r.name, "The "+r.name+" completed successfully again.")
	r.alerts.Resolve(ctx, "scheduler:panic:"+r.name,
		"Scheduler job recovered after panic: "+r.name, "The "+r.name+" completed successfully again.")
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
