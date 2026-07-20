package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
)

type schedulerAlertRecorder struct {
	events []notify.Event
}

func (a *schedulerAlertRecorder) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *schedulerAlertRecorder) Resolve(context.Context, string, string, string) {}

func TestRunnerRecoversPanicAndAlerts(t *testing.T) {
	alerts := &schedulerAlertRecorder{}
	runner := newRunner("test job", time.Hour, time.Second, func(context.Context) {
		panic("boom")
	}, alerts)

	runner.runOnce()
	if len(alerts.events) != 1 {
		t.Fatalf("event count = %d, want 1", len(alerts.events))
	}
	event := alerts.events[0]
	if event.Key != "scheduler:panic:test job" || event.Kind != notify.KindImmediate {
		t.Fatalf("event = %+v", event)
	}
}
