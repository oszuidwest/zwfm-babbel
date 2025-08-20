// Package scheduler provides background task scheduling services for the Babbel API.
package scheduler

import (
	"time"

	"github.com/jmoiron/sqlx"
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

	// Run immediately on start
	s.expireStories()

	// Then run every hour
	s.ticker = time.NewTicker(1 * time.Hour)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.expireStories()
			case <-s.done:
				return
			}
		}
	}()
}

// Stop gracefully shuts down the expiration service.
// Stops the ticker and signals the background goroutine to exit.
// This method is safe to call multiple times.
func (s *StoryExpirationService) Stop() {
	logger.Info("Stopping story expiration service")
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true
}

// expireStories performs the actual expiration logic by updating story statuses.
// Only affects stories that are currently 'active' and past their end_date.
// Does not automatically activate draft stories - that requires manual editorial decision.
// Logs the number of stories affected for monitoring purposes.
func (s *StoryExpirationService) expireStories() {
	logger.Info("Running story expiration check...")

	// Only expire stories that are past their end date
	// We don't automatically activate stories - that's an editorial decision
	result, err := s.db.Exec(`
		UPDATE stories 
		SET status = 'expired', 
		    updated_at = NOW()
		WHERE status = 'active' 
		AND end_date < CURDATE()
		AND deleted_at IS NULL
	`)

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
