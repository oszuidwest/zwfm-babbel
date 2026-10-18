package scheduler

import (
	"context"
	"errors"
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
	alerts := &schedulerAlertRecorder{}
	started, finished := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	r := newRunner("stopping job", time.Hour, 2*time.Second, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		result <- ctx.Err()
		close(finished)
		return ctx.Err()
	}, alerts)
	startReturned := make(chan struct{})
	go func() { r.Start(); close(startReturned) }()
	<-started
	r.Stop()
	select {
	case <-finished:
	default:
		t.Error("Stop returned while the job was still running")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Errorf("job context = %v, want cancellation by Stop", err)
	}
	<-startReturned
	if len(alerts.events) != 0 || len(alerts.resolved) != 0 {
		t.Fatalf("alerts = %+v, resolved = %v; want none for shutdown", alerts.events, alerts.resolved)
	}
}

func TestRunnerStoppedBeforeStartDoesNotRun(t *testing.T) {
	t.Parallel()
	r := newRunner("unused job", time.Hour, time.Second, func(context.Context) error {
		t.Error("job ran after Stop")
		return nil
	}, notify.Discard)
	r.Stop()
	r.Start()
	r.Stop()
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
