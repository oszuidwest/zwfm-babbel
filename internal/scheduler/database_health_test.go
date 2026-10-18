package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"testing"

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
	// The exported HTTP-health helper retains its original behavior.
	if err := CheckDatabase(ctx, s.db, alerts); !errors.Is(err, context.Canceled) || len(alerts.events) != 1 {
		t.Fatalf("CheckDatabase = %v, events = %+v; want original public behavior", err, alerts.events)
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
