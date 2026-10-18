package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func TestCheckDatabaseAcceptsNilAlerter(t *testing.T) {
	db := &gorm.DB{Config: &gorm.Config{}}

	err := CheckDatabase(t.Context(), db, nil)
	if !errors.Is(err, gorm.ErrInvalidDB) {
		t.Fatalf("CheckDatabase error = %v, want invalid database", err)
	}
}

func TestDatabaseHealthShutdownCancellationDoesNotNotify(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	alerts := &schedulerAlertRecorder{}
	s := NewDatabaseHealthService(offlineDB(t), alerts)
	if err := s.check(ctx); err != nil || len(alerts.events) != 0 || len(alerts.resolved) != 0 || logs.Len() != 0 {
		t.Fatalf("check = %v, events = %+v, resolved = %v, logs = %s", err, alerts.events, alerts.resolved, logs)
	}
	// /health uses this same exported helper, with the request context.
	if err := CheckDatabase(ctx, s.db, alerts); !errors.Is(err, context.Canceled) || len(alerts.events) != 0 || len(alerts.resolved) != 0 || logs.Len() != 0 {
		t.Fatalf("CheckDatabase = %v, events = %+v, resolved = %v, logs = %s; want silent cancellation", err, alerts.events, alerts.resolved, logs)
	}
}

func TestCheckDatabaseFailuresStillNotify(t *testing.T) {
	for _, name := range []string{"deadline", "live caller", "independent failure after cancellation"} {
		t.Run(name, func(t *testing.T) {
			logs := testutil.CaptureLogs(t, slog.LevelError)
			ctx := t.Context()
			db := offlineDB(t)
			var want error
			switch name {
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				want = context.DeadlineExceeded
			case "independent failure after cancellation":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				db = &gorm.DB{Config: &gorm.Config{}}
				want = gorm.ErrInvalidDB
			}
			alerts := &schedulerAlertRecorder{}
			err := CheckDatabase(ctx, db, alerts)
			if err == nil || (want != nil && !errors.Is(err, want)) || len(alerts.events) != 1 || len(alerts.resolved) != 0 || logs.Len() == 0 {
				t.Fatalf("error = %v, events = %+v, resolved = %v, logs = %s", err, alerts.events, alerts.resolved, logs)
			}
			if event := alerts.events[0]; event.Key != "database:connection" || !event.RequiresThreshold {
				t.Fatalf("event = %+v, want thresholded database incident", event)
			}
		})
	}
}

func TestDatabaseHealthIndependentFailureStillNotifiesDuringStop(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	alerts := &schedulerAlertRecorder{}
	s := NewDatabaseHealthService(&gorm.DB{Config: &gorm.Config{}}, alerts)
	if err := s.check(ctx); err != nil || len(alerts.events) != 1 || alerts.events[0].Details != gorm.ErrInvalidDB.Error() {
		t.Fatalf("check = %v, events = %+v; want independent invalid-database error", err, alerts.events)
	}
}
