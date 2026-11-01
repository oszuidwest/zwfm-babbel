package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/go-sql-driver/mysql"
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

func TestCheckDatabaseCallerCancellationDoesNotNotify(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	ctx, cancel := context.WithCancel(t.Context())
	// The caller hangs up while the ping is still connecting.
	db := dialDB(t, func(ctx context.Context, _, _ string) (net.Conn, error) {
		cancel()
		return nil, ctx.Err()
	})
	alerts := &schedulerAlertRecorder{}
	err := CheckDatabase(ctx, db, alerts)
	if !errors.Is(err, context.Canceled) || len(alerts.events) != 0 || len(alerts.resolved) != 0 || logs.Len() != 0 {
		t.Fatalf("CheckDatabase = %v, events = %+v, resolved = %v, logs = %s", err, alerts.events, alerts.resolved, logs)
	}
}

func TestCheckDatabaseDeadlineStillNotifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 0)
	defer cancel()
	alerts := &schedulerAlertRecorder{}
	if err := CheckDatabase(ctx, offlineDB(t), alerts); !errors.Is(err, context.DeadlineExceeded) || len(alerts.events) != 1 {
		t.Fatalf("CheckDatabase = %v, events = %+v; want a deadline to count", err, alerts.events)
	}
}

func TestCheckDatabaseCancellationWithLiveContextNotifies(t *testing.T) {
	db := dialDB(t, func(context.Context, string, string) (net.Conn, error) { return nil, context.Canceled })
	alerts := &schedulerAlertRecorder{}
	if err := CheckDatabase(t.Context(), db, alerts); !errors.Is(err, context.Canceled) || len(alerts.events) != 1 {
		t.Fatalf("CheckDatabase = %v, events = %+v; want a cancellation the caller did not ask for to count", err, alerts.events)
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

// dialDB returns a database whose connection attempts call dial.
func dialDB(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *gorm.DB {
	t.Helper()
	cfg := mysql.NewConfig()
	cfg.DialFunc = dial
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := sql.OpenDB(connector)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return &gorm.DB{Config: &gorm.Config{ConnPool: sqlDB}}
}
