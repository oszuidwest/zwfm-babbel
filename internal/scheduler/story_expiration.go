// Package scheduler provides background task scheduling services for the Babbel API.
package scheduler

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
)

// StoryExpirationService handles automatic expiration of stories past their end date
type StoryExpirationService struct {
	db     *sqlx.DB
	ticker *time.Ticker
	done   chan bool
}

// NewStoryExpirationService creates a new story expiration service
func NewStoryExpirationService(db *sqlx.DB) *StoryExpirationService {
	return &StoryExpirationService{
		db:   db,
		done: make(chan bool),
	}
}

// Start begins the hourly expiration check
func (s *StoryExpirationService) Start() {
	log.Println("Starting story expiration service (runs hourly)")

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

// Stop halts the expiration service
func (s *StoryExpirationService) Stop() {
	log.Println("Stopping story expiration service")
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.done <- true
}

// expireStories updates the status of stories that are past their end date
func (s *StoryExpirationService) expireStories() {
	log.Println("Running story expiration check...")

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
		log.Printf("ERROR: Failed to expire stories: %v", err)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		log.Printf("ERROR: Failed to get affected rows: %v", err)
		return
	}

	if affected > 0 {
		log.Printf("Expired %d stories past their end date", affected)
	}
}
