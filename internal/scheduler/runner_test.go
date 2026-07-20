package scheduler

import (
	"context"
	"errors"
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

	runner.runOnce()
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "scheduler:panic:test job" || event.Kind != notify.KindImmediate {
		t.Fatalf("event = %+v", event)
	}

	shouldPanic = false
	runner.runOnce()
	if !containsString(alerts.resolved, "scheduler:panic:test job") {
		t.Fatalf("resolved = %v, want scheduler panic recovery", alerts.resolved)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRunnerAlertsOnErrorAndResolvesOnSuccess(t *testing.T) {
	alerts := &schedulerAlertRecorder{}
	jobErr := errors.New("job failed")
	runner := newRunner("test job", time.Hour, time.Second, func(context.Context) error {
		return jobErr
	}, alerts)

	runner.runOnce()
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "scheduler:test job" || event.Kind != notify.KindContinuous {
		t.Fatalf("event = %+v", event)
	}

	runner.fn = func(context.Context) error { return nil }
	runner.runOnce()
	if !containsString(alerts.resolved, "scheduler:test job") {
		t.Fatalf("resolved = %v, want scheduler job recovery", alerts.resolved)
	}
}
