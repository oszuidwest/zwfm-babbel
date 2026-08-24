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

	ticker   *time.Ticker
	done     chan bool
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
				Details: fmt.Sprint(recovered),
			})
		}
	}()
	if err := r.fn(ctx); err != nil {
		r.alerts.Alert(ctx, notify.Event{
			Key: "scheduler:" + r.name, Summary: "Scheduler job repeatedly fails: " + r.name, Details: err.Error(),
			RequiresThreshold: true,
		})
		return
	}
	r.alerts.Resolve(ctx, "scheduler:"+r.name,
		"Scheduler job recovered: "+r.name, "The "+r.name+" completed successfully again.")
	r.alerts.Resolve(ctx, "scheduler:panic:"+r.name,
		"Scheduler job recovered after panic: "+r.name, "The "+r.name+" completed successfully again.")
}

// Stop signals shutdown once, waiting at most five seconds for the receiver.
func (r *runner) Stop() {
	r.stopOnce.Do(func() {
		logger.Info("Stopping " + r.name)
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
