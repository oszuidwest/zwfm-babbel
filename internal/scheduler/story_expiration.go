// Package scheduler provides background task scheduling services for the Babbel API.
package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryExpirationService handles automatic expiration of stories past their end date.
// Runs as a background service that periodically checks for stories that should be expired
// and updates their status from 'active' to 'expired'. This ensures bulletins only include current content.
type StoryExpirationService struct {
	// db provides database access for story status updates
	db *sqlx.DB
	// ticker controls the hourly execution schedule
	ticker *time.Ticker
	// done channel enables graceful shutdown signaling
	done chan bool
	// stopOnce ensures Stop() can only be called once, preventing double-stop race conditions
	stopOnce sync.Once
}

// NewStoryExpirationService creates a new background service for story expiration management.
// The service must be started with [StoryExpirationService.Start] to begin operations.
func NewStoryExpirationService(db *sqlx.DB) *StoryExpirationService {
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
	s.expireStories(ctx)
	cancel()

	// Then run every hour
	s.ticker = time.NewTicker(1 * time.Hour)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				s.expireStories(ctx)
				cancel()
			case <-s.done:
				return
			}
		}
	}()
}

// Stop gracefully shuts down the expiration service.
// Uses sync.Once to prevent double-stop race conditions and a timeout to prevent deadlock.
func (s *StoryExpirationService) Stop() {
	s.stopOnce.Do(func() {
		logger.Info("Stopping story expiration service")
		if s.ticker != nil {
			s.ticker.Stop()
		}
		select {
		case s.done <- true:
		case <-time.After(5 * time.Second):
			logger.Info("Story expiration service shutdown timeout")
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
	result, err := s.db.ExecContext(ctx, `
		UPDATE stories
		SET status = ?,
		    updated_at = NOW()
		WHERE status = ?
		AND end_date < CURDATE()
		AND deleted_at IS NULL
	`, models.StoryStatusExpired, models.StoryStatusActive)

	if err != nil {
		logger.Error("Failed to expire stories: %v", err)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		logger.Error("Failed to get affected rows: %v", err)
		return
	}

	if affected > 0 {
		logger.Info("Expired %d stories past their end date", affected)
	}
}
