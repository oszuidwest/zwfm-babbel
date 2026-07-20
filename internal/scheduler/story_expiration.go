// Package scheduler provides background task scheduling services for the Babbel API.
package scheduler

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryExpirationService handles automatic expiration of stories past their end date.
// Runs as a background service that periodically checks for stories that should be expired
// and updates their status from 'active' to 'expired'. This keeps bulletins
// limited to current content.
type StoryExpirationService struct {
	repo   *repository.StoryRepository
	runner *runner
	alerts notify.Alerter
}

// NewStoryExpirationService returns a stopped expiration service.
// Call [StoryExpirationService.Start] to begin hourly checks.
func NewStoryExpirationService(db *gorm.DB, alerts ...notify.Alerter) *StoryExpirationService {
	var alertSink notify.Alerter
	if len(alerts) > 0 {
		alertSink = alerts[0]
	}
	s := &StoryExpirationService{
		repo:   repository.NewStoryRepository(db),
		alerts: alertSink,
	}
	s.runner = newRunner("story expiration service", 1*time.Hour, 30*time.Second, s.expireStories, alertSink)
	return s
}

// Start runs expiration immediately and then every hour in a background
// goroutine.
func (s *StoryExpirationService) Start() {
	logger.Info("Starting story expiration service (runs hourly)")
	s.runner.Start()
}

// Stop gracefully shuts down the expiration service.
func (s *StoryExpirationService) Stop() {
	s.runner.Stop()
}

// expireStories marks active stories past end_date as expired.
// Draft stories are not activated automatically because publication remains an
// editorial decision.
func (s *StoryExpirationService) expireStories(ctx context.Context) {
	logger.Info("Running story expiration check...")

	count, err := s.repo.ExpireStoriesPastEndDate(ctx)
	if err != nil {
		logger.Error("Failed to expire stories", "error", err)
		if s.alerts != nil {
			s.alerts.Alert(ctx, notify.Event{
				Key: "scheduler:story-expiration", Summary: "Story expiration job repeatedly fails",
				Details: err.Error(), Kind: notify.KindContinuous,
			})
		}
		return
	}
	if s.alerts != nil {
		s.alerts.Resolve(ctx, "scheduler:story-expiration", "Story expiration job recovered", "Expired stories are being processed again.")
	}

	if count > 0 {
		logger.Info("Expired stories past their end date", "count", count)
	}
}
