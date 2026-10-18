package scheduler

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
)

type schedulerAlertRecorder struct {
	events   []notify.Event
	resolved []string
}

func (a *schedulerAlertRecorder) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *schedulerAlertRecorder) Resolve(_ context.Context, key, _, _ string) {
	a.resolved = append(a.resolved, key)
}

func TestRunnerRecoversPanicAndAlerts(t *testing.T) {
	alerts := &schedulerAlertRecorder{}
	shouldPanic := true
	runner := newRunner("test job", time.Hour, time.Second, func(context.Context) error {
		if shouldPanic {
			panic("boom")
		}
		return nil
	}, alerts)

	runner.runOnce(t.Context())
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "scheduler:panic:test job" || event.RequiresThreshold {
		t.Fatalf("event = %+v", event)
	}

	shouldPanic = false
	runner.runOnce(t.Context())
	if !slices.Contains(alerts.resolved, "scheduler:panic:test job") {
		t.Fatalf("resolved = %v, want scheduler panic recovery", alerts.resolved)
	}
}

func TestRunnerAlertsOnFirstErrorAndResolvesOnSuccess(t *testing.T) {
	alerts := &schedulerAlertRecorder{}
	jobErr := errors.New("job failed")
	runner := newRunner("test job", time.Hour, time.Second, func(context.Context) error {
		return jobErr
	}, alerts)

	runner.runOnce(t.Context())
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "scheduler:test job" || event.RequiresThreshold || event.Details != jobErr.Error() {
		t.Fatalf("event = %+v, want immediate scheduler alert", event)
	}
	if len(alerts.resolved) != 0 {
		t.Fatalf("resolved after failure = %v, want none", alerts.resolved)
	}

	runner.fn = func(context.Context) error { return nil }
	runner.runOnce(t.Context())
	if !slices.Contains(alerts.resolved, "scheduler:test job") {
		t.Fatalf("resolved = %v, want scheduler job recovery", alerts.resolved)
	}
}

func TestRunnerStopCancelsAndWaitsForRunningJob(t *testing.T) {
	t.Parallel()
	for name, failure := range map[string]error{"cancellation only": nil, "joined failure": errors.New("storage unreadable")} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			alerts := &schedulerAlertRecorder{}
			started, result := make(chan struct{}), make(chan error, 1)
			r := newRunner("stopping job", time.Hour, 2*time.Second, func(ctx context.Context) error {
				close(started)
				<-ctx.Done()
				result <- ctx.Err()
				return errors.Join(failure, fmt.Errorf("query: %w", ctx.Err()))
			}, alerts)
			go r.Start()
			<-started
			r.Stop()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("job context = %v, want cancellation by Stop", err)
				}
			default:
				t.Fatal("Stop returned while the job was still running")
			}
			// Shutdown alone is silent; a failure joined with it still alerts.
			if wantEvents := failure != nil; (len(alerts.events) == 1) != wantEvents || len(alerts.events) > 1 || len(alerts.resolved) != 0 {
				t.Fatalf("alerts = %+v, resolved = %v; want an alert only for the joined failure", alerts.events, alerts.resolved)
			}
		})
	}
}

func TestRunnerStopDuringTickerJobDoesNotNotify(t *testing.T) {
	t.Parallel()
	alerts := &schedulerAlertRecorder{}
	started := make(chan struct{})
	runs := 0
	r := newRunner("ticker job", time.Millisecond, time.Second, func(ctx context.Context) error {
		runs++
		if runs == 1 {
			return nil
		}
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, alerts)
	r.Start()
	events, resolved := len(alerts.events), len(alerts.resolved)
	<-started
	r.Stop()
	if runs != 2 || len(alerts.events) != events || len(alerts.resolved) != resolved {
		t.Fatalf("runs = %d, events = %+v, resolved = %v; shutdown must not notify", runs, alerts.events, alerts.resolved)
	}
}

func TestRunnerStartTwiceRunsOneLoop(t *testing.T) {
	runs := 0
	r := newRunner("started twice", time.Hour, time.Second, func(context.Context) error {
		runs++
		return nil
	}, notify.Discard)

	r.Start()
	r.Start()
	r.Stop() // A second loop would close done again and panic.
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

func TestRunnerStillAlertsForDeadlineOrIndependentCancellation(t *testing.T) {
	t.Parallel()
	for _, err := range []error{context.DeadlineExceeded, context.Canceled} {
		t.Run(err.Error(), func(t *testing.T) {
			t.Parallel()
			alerts := &schedulerAlertRecorder{}
			r := newRunner("failed job", time.Hour, time.Second, func(context.Context) error { return err }, alerts)
			r.runOnce(t.Context())
			if len(alerts.events) != 1 || alerts.events[0].RequiresThreshold {
				t.Fatalf("events = %+v, want one immediate failure alert", alerts.events)
			}
		})
	}
}
