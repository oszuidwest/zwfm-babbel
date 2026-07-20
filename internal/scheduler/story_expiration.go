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
}

// NewStoryExpirationService returns a stopped expiration service.
// Call [StoryExpirationService.Start] to begin hourly checks.
func NewStoryExpirationService(db *gorm.DB, alerts notify.Alerter) *StoryExpirationService {
	alerts = notify.OrDiscard(alerts)
	s := &StoryExpirationService{
		repo: repository.NewStoryRepository(db),
	}
	s.runner = newRunner("story expiration service", 1*time.Hour, 30*time.Second, s.expireStories, alerts)
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
// editorial decision. The runner turns a returned error into an alert.
func (s *StoryExpirationService) expireStories(ctx context.Context) error {
	logger.Info("Running story expiration check...")

	count, err := s.repo.ExpireStoriesPastEndDate(ctx)
	if err != nil {
		logger.Error("Failed to expire stories", "error", err)
		return err
	}

	if count > 0 {
		logger.Info("Expired stories past their end date", "count", count)
	}
	return nil
}
