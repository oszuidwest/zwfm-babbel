package scheduler

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// DatabaseHealthService detects connection loss independently of HTTP traffic.
type DatabaseHealthService struct {
	db     *gorm.DB
	alerts notify.Alerter
	runner *runner
}

// NewDatabaseHealthService returns a stopped database health monitor.
func NewDatabaseHealthService(db *gorm.DB, alerts notify.Alerter) *DatabaseHealthService {
	s := &DatabaseHealthService{db: db, alerts: alerts}
	s.runner = newRunner("database health service", time.Minute, 10*time.Second, s.check, alerts)
	return s
}

func (s *DatabaseHealthService) Start() { s.runner.Start() }
func (s *DatabaseHealthService) Stop()  { s.runner.Stop() }

func (s *DatabaseHealthService) check(ctx context.Context) {
	sqlDB, err := s.db.DB()
	if err == nil {
		err = sqlDB.PingContext(ctx)
	}
	if err != nil {
		logger.Error("Database health check failed", "error", err)
		if s.alerts != nil {
			s.alerts.Alert(ctx, notify.Event{
				Key: "database:connection", Summary: "Database connection repeatedly fails",
				Details: err.Error(), Kind: notify.KindContinuous,
			})
		}
		return
	}
	if s.alerts != nil {
		s.alerts.Resolve(ctx, "database:connection", "Database connection recovered", "Database ping succeeds again.")
	}
}
