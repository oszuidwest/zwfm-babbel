package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// runner executes a job immediately on Start and then at a fixed interval in a
// background goroutine until Stop is called. Each run receives a context that
// is cancelled after runTimeout or by Stop. A run that returns an error or
// panics raises an immediate operational alert; a successful run resolves it.
type runner struct {
	name       string
	interval   time.Duration
	runTimeout time.Duration
	fn         func(ctx context.Context) error
	alerts     notify.Alerter

	ctx       context.Context // cancelled by Stop
	cancel    context.CancelFunc
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// newRunner returns a stopped runner that executes fn every interval.
// alerts must be non-nil; pass notify.Discard when notifications are absent.
func newRunner(name string, interval, runTimeout time.Duration, fn func(ctx context.Context) error, alerts notify.Alerter) *runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &runner{
		name:       name,
		interval:   interval,
		runTimeout: runTimeout,
		fn:         fn,
		alerts:     alerts,
		ctx:        ctx,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
}

// Start runs the job immediately and then every interval in a background
// goroutine. Later calls do nothing.
func (r *runner) Start() {
	r.startOnce.Do(func() {
		r.runOnce(r.ctx)

		go func() {
			defer close(r.done)
			ticker := time.NewTicker(r.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					r.runOnce(r.ctx)
				case <-r.ctx.Done():
					return
				}
			}
		}()
	})
}

// runOnce executes the job with a per-run timeout context and maintains the
// job's shared failure/recovery alert state.
func (r *runner) runOnce(parent context.Context) {
	if parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, r.runTimeout)
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
		if parent.Err() != nil && onlyCanceled(err) {
			return // Stop cancelled the job; this is not an operational failure.
		}
		// Immediate, not thresholded: the jobs that can fail here run hourly
		// or daily, too rarely to reach the default failure threshold within
		// its window. A persistent failure alerts again on the first run after
		// each cooldown.
		r.alerts.Alert(ctx, notify.Event{
			Key: "scheduler:" + r.name, Summary: "Scheduler job failed: " + r.name, Details: err.Error(),
		})
		return
	}
	if parent.Err() != nil {
		return // A shutdown is not evidence that a prior incident recovered.
	}
	r.alerts.Resolve(ctx, "scheduler:"+r.name,
		"Scheduler job recovered: "+r.name, "The "+r.name+" completed successfully again.")
	r.alerts.Resolve(ctx, "scheduler:panic:"+r.name,
		"Scheduler job recovered after panic: "+r.name, "The "+r.name+" completed successfully again.")
}

// Stop cancels the active job and waits at most five seconds for the loop to
// exit.
func (r *runner) Stop() {
	r.stopOnce.Do(func() {
		logger.Info("Stopping " + r.name)
		r.cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			logger.Info("Shutdown timeout", "service", r.name)
		}
	})
}

// onlyCanceled reports whether err consists of cancellations only, so a
// failure joined with Stop's cancellation still alerts.
func onlyCanceled(err error) bool {
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		for _, inner := range joined.Unwrap() {
			if !onlyCanceled(inner) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, context.Canceled)
}
