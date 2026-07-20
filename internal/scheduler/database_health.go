package scheduler

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// CheckDatabase pings the database and maintains the shared
// "database:connection" alert state. Both the periodic health service and the
// /health endpoint use it, so one connection loss produces one alert/recovery
// pair regardless of which path observes it first.
func CheckDatabase(ctx context.Context, db *gorm.DB, alerts notify.Alerter) error {
	sqlDB, err := db.DB()
	if err == nil {
		err = sqlDB.PingContext(ctx)
	}
	if err != nil {
		logger.Error("Database health check failed", "error", err)
		alerts.Alert(ctx, notify.Event{
			Key: "database:connection", Summary: "Database connection repeatedly fails",
			Details: err.Error(), Kind: notify.KindContinuous,
		})
		return err
	}
	alerts.Resolve(ctx, "database:connection", "Database connection recovered", "Database ping succeeds again.")
	return nil
}

// DatabaseHealthService detects connection loss independently of HTTP traffic.
type DatabaseHealthService struct {
	db     *gorm.DB
	alerts notify.Alerter
	runner *runner
}

// NewDatabaseHealthService returns a stopped database health monitor.
func NewDatabaseHealthService(db *gorm.DB, alerts notify.Alerter) *DatabaseHealthService {
	alerts = notify.OrDiscard(alerts)
	s := &DatabaseHealthService{db: db, alerts: alerts}
	s.runner = newRunner("database health service", time.Minute, 10*time.Second, s.check, alerts)
	return s
}

// Start begins periodic health checks.
func (s *DatabaseHealthService) Start() { s.runner.Start() }

// Stop gracefully shuts down the health monitor.
func (s *DatabaseHealthService) Stop() { s.runner.Stop() }

func (s *DatabaseHealthService) check(ctx context.Context) error {
	// CheckDatabase alerts under the shared "database:connection" key; always
	// return nil so the runner does not raise a duplicate generic alert.
	_ = CheckDatabase(ctx, s.db, s.alerts)
	return nil
}
