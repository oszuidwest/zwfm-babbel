// Package scheduler provides background task scheduling services for the Babbel API.
package scheduler

import (
	"context"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryExpirationService handles automatic expiration of stories past their end date.
// Runs as a background service that periodically checks for stories that should be expired
// and updates their status from 'active' to 'expired'. This keeps bulletins
// limited to current content.
type StoryExpirationService struct {
	db     *gorm.DB
	ticker *time.Ticker
	done   chan bool
	// stopOnce prevents double-stop race conditions when Stop is called more
	// than once.
	stopOnce sync.Once
}

// NewStoryExpirationService returns a stopped expiration service.
// Call [StoryExpirationService.Start] to begin hourly checks.
func NewStoryExpirationService(db *gorm.DB) *StoryExpirationService {
	return &StoryExpirationService{
		db:   db,
		done: make(chan bool),
	}
}

// Start runs expiration immediately and then every hour in a background
// goroutine.
func (s *StoryExpirationService) Start() {
	logger.Info("Starting story expiration service (runs hourly)")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.expireStories(ctx)

	s.ticker = time.NewTicker(1 * time.Hour)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					s.expireStories(ctx)
				}()
			case <-s.done:
				return
			}
		}
	}()
}

// Stop gracefully shuts down the expiration service.
// Uses sync.Once to prevent double-stop race conditions and a timeout to prevent deadlock.
// Sends the done signal before stopping the ticker to avoid a race condition where the
// goroutine might read from a closed ticker channel before receiving the shutdown signal.
func (s *StoryExpirationService) Stop() {
	s.stopOnce.Do(func() {
		logger.Info("Stopping story expiration service")
		// Signal done FIRST to ensure goroutine exits before we stop the ticker.
		// This prevents a race condition where ticker.C could be read after Stop().
		select {
		case s.done <- true:
		case <-time.After(5 * time.Second):
			logger.Info("Story expiration service shutdown timeout")
		}
		if s.ticker != nil {
			s.ticker.Stop()
		}
	})
}

// expireStories marks active stories past end_date as expired.
// Draft stories are not activated automatically because publication remains an
// editorial decision.
func (s *StoryExpirationService) expireStories(ctx context.Context) {
	logger.Info("Running story expiration check...")

	// GORM automatically excludes soft-deleted records (deleted_at IS NULL)
	result := s.db.WithContext(ctx).
		Model(&models.Story{}).
		Where("status = ?", models.StoryStatusActive).
		Where("end_date < CURDATE()").
		Update("status", models.StoryStatusExpired)

	if result.Error != nil {
		logger.Error("Failed to expire stories", "error", result.Error)
		return
	}

	if result.RowsAffected > 0 {
		logger.Info("Expired stories past their end date", "count", result.RowsAffected)
	}
}
