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
// and updates their status from 'active' to 'expired'. This ensures bulletins only include current content.
type StoryExpirationService struct {
	// db provides GORM database access for story status updates
	db *gorm.DB
	// ticker controls the hourly execution schedule
	ticker *time.Ticker
	// done channel enables graceful shutdown signaling
	done chan bool
	// stopOnce ensures Stop() can only be called once, preventing double-stop race conditions
	stopOnce sync.Once
}

// NewStoryExpirationService creates a new background service for story expiration management.
// The service must be started with [StoryExpirationService.Start] to begin operations.
func NewStoryExpirationService(db *gorm.DB) *StoryExpirationService {
	return &StoryExpirationService{
		db:   db,
		done: make(chan bool),
	}
}

// Start begins the background expiration service with immediate execution and hourly intervals.
// The service runs in a separate goroutine and can be stopped with [StoryExpirationService.Stop].
// Logs all operations for monitoring and debugging.
func (s *StoryExpirationService) Start() {
	logger.Info("Starting story expiration service (runs hourly)")

	// Run immediately on start with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.expireStories(ctx)

	// Then run every hour
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

// expireStories performs the actual expiration logic by updating story statuses.
// Only affects stories that are currently 'active' and past their end_date.
// Does not automatically activate draft stories - that requires manual editorial decision.
// Logs the number of stories affected for monitoring purposes.
func (s *StoryExpirationService) expireStories(ctx context.Context) {
	logger.Info("Running story expiration check...")

	// Update active stories with past end dates to expired status
	// GORM automatically excludes soft-deleted records (deleted_at IS NULL)
	result := s.db.WithContext(ctx).
		Model(&models.Story{}).
		Where("status = ?", models.StoryStatusActive).
		Where("end_date < CURDATE()").
		Update("status", models.StoryStatusExpired)

	if result.Error != nil {
		logger.Error("Failed to expire stories: %v", result.Error)
		return
	}

	if result.RowsAffected > 0 {
		logger.Info("Expired %d stories past their end date", result.RowsAffected)
	}
}
