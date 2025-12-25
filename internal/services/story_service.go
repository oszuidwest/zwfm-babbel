// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryService handles business logic for news story operations.
type StoryService struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
}

// NewStoryService creates a new story service instance.
func NewStoryService(db *sqlx.DB, audioSvc *audio.Service, cfg *config.Config) *StoryService {
	return &StoryService{
		db:       db,
		audioSvc: audioSvc,
		config:   cfg,
	}
}

// CreateStoryRequest contains the data needed to create a new story.
type CreateStoryRequest struct {
	Title     string
	Text      string
	VoiceID   *int
	Status    string
	StartDate string // Date in YYYY-MM-DD format
	EndDate   string // Date in YYYY-MM-DD format
	Weekdays  map[string]bool
	Metadata  map[string]interface{}
}

// UpdateStoryRequest contains the data needed to update an existing story.
type UpdateStoryRequest struct {
	Title     *string
	Text      *string
	VoiceID   *int
	Status    *string
	StartDate *string // Date in YYYY-MM-DD format
	EndDate   *string // Date in YYYY-MM-DD format
	Weekdays  map[string]bool
	Metadata  map[string]interface{}
}

// Create creates a new story in the database.
func (s *StoryService) Create(ctx context.Context, req *CreateStoryRequest) (*models.Story, error) {
	// Validate voice exists if provided
	if req.VoiceID != nil {
		if err := s.validateVoiceExists(ctx, *req.VoiceID); err != nil {
			return nil, err
		}
	}

	// Parse and validate start date
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid start_date format, must be YYYY-MM-DD", ErrInvalidInput)
	}

	// Parse and validate end date
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid end_date format, must be YYYY-MM-DD", ErrInvalidInput)
	}

	// Validate date range
	if endDate.Before(startDate) {
		return nil, fmt.Errorf("%w: end date cannot be before start date", ErrInvalidInput)
	}

	// Extract weekday booleans from map
	monday, tuesday, wednesday, thursday, friday, saturday, sunday := s.extractWeekdays(req.Weekdays)

	// Handle metadata - MySQL JSON column requires NULL not empty
	var metadataValue interface{}
	if len(req.Metadata) == 0 {
		metadataValue = nil
	} else {
		// Convert map to JSON string (simple approach - could use json.Marshal)
		metadataValue = req.Metadata
	}

	// Insert story into database
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO stories (title, text, voice_id, status, start_date, end_date,
			monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Title, req.Text, req.VoiceID, req.Status, startDate, endDate,
		monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadataValue)

	if err != nil {
		logger.Error("Database error creating story: %v", err)
		return nil, s.handleDatabaseError(err)
	}

	storyID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get last insert ID", ErrDatabaseError)
	}

	// Fetch and return the created story
	return s.GetByID(ctx, int(storyID))
}

// Update updates an existing story.
func (s *StoryService) Update(ctx context.Context, id int, req *UpdateStoryRequest) (*models.Story, error) {
	// Verify story exists
	if _, err := s.GetByID(ctx, id); err != nil {
		return nil, err
	}

	// Parse dates if provided and validate date range
	var startDate, endDate *time.Time
	if req.StartDate != nil {
		parsed, err := time.Parse("2006-01-02", *req.StartDate)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid start_date format, must be YYYY-MM-DD", ErrInvalidInput)
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := time.Parse("2006-01-02", *req.EndDate)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid end_date format, must be YYYY-MM-DD", ErrInvalidInput)
		}
		endDate = &parsed
	}

	// Validate date range if both dates provided
	if startDate != nil && endDate != nil {
		if endDate.Before(*startDate) {
			return nil, fmt.Errorf("%w: end date cannot be before start date", ErrInvalidInput)
		}
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	// Handle each field that may be updated
	if req.Title != nil {
		updates = append(updates, "title = ?")
		args = append(args, *req.Title)
	}

	if req.Text != nil {
		updates = append(updates, "text = ?")
		args = append(args, *req.Text)
	}

	if req.Status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *req.Status)
	}

	if req.VoiceID != nil {
		if err := s.validateVoiceExists(ctx, *req.VoiceID); err != nil {
			return nil, err
		}
		updates = append(updates, "voice_id = ?")
		args = append(args, *req.VoiceID)
	}

	if startDate != nil {
		updates = append(updates, "start_date = ?")
		args = append(args, *startDate)
	}

	if endDate != nil {
		updates = append(updates, "end_date = ?")
		args = append(args, *endDate)
	}

	// Handle weekdays updates
	if len(req.Weekdays) > 0 {
		updates = append(updates, "monday = ?, tuesday = ?, wednesday = ?, thursday = ?, friday = ?, saturday = ?, sunday = ?")
		monday, tuesday, wednesday, thursday, friday, saturday, sunday := s.extractWeekdays(req.Weekdays)
		args = append(args, monday, tuesday, wednesday, thursday, friday, saturday, sunday)
	}

	if req.Metadata != nil {
		updates = append(updates, "metadata = ?")
		if len(req.Metadata) == 0 {
			args = append(args, nil)
		} else {
			args = append(args, req.Metadata)
		}
	}

	if len(updates) == 0 {
		return nil, fmt.Errorf("%w: no fields to update", ErrInvalidInput)
	}

	// Execute update
	query := "UPDATE stories SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		logger.Error("Database error updating story: %v", err)
		return nil, s.handleDatabaseError(err)
	}

	// Fetch and return the updated story
	return s.GetByID(ctx, id)
}

// GetByID retrieves a story by its ID.
func (s *StoryService) GetByID(ctx context.Context, id int) (*models.Story, error) {
	var story models.Story
	query := utils.BuildStoryQuery("s.id = ?", true)

	if err := s.db.GetContext(ctx, &story, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: story with id %d", ErrNotFound, id)
		}
		logger.Error("Database error fetching story %d: %v", id, err)
		return nil, fmt.Errorf("%w: failed to fetch story", ErrDatabaseError)
	}

	return &story, nil
}

// SoftDelete marks a story as deleted by setting the deleted_at timestamp.
func (s *StoryService) SoftDelete(ctx context.Context, id int) error {
	// Verify story exists
	if _, err := s.GetByID(ctx, id); err != nil {
		return err
	}

	_, err := s.db.ExecContext(ctx, "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error deleting story %d: %v", id, err)
		return fmt.Errorf("%w: failed to delete story", ErrDatabaseError)
	}

	return nil
}

// Restore restores a soft-deleted story by clearing the deleted_at timestamp.
func (s *StoryService) Restore(ctx context.Context, id int) error {
	// Verify story exists (even if deleted)
	var exists bool
	err := s.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stories WHERE id = ?)", id)
	if err != nil || !exists {
		return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
	}

	_, err = s.db.ExecContext(ctx, "UPDATE stories SET deleted_at = NULL WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error restoring story %d: %v", id, err)
		return fmt.Errorf("%w: failed to restore story", ErrDatabaseError)
	}

	return nil
}

// ProcessAudio processes an uploaded audio file for a story.
// The tempPath should be a validated temporary file path.
// This method will convert the audio to standardized WAV format and update the story record.
func (s *StoryService) ProcessAudio(ctx context.Context, storyID int, tempPath string) error {
	// Verify story exists
	if _, err := s.GetByID(ctx, storyID); err != nil {
		return err
	}

	// Process audio with audio service (convert to mono WAV)
	outputPath := utils.GetStoryPath(s.config, storyID)
	filename, duration, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 1)
	if err != nil {
		logger.Error("Failed to process story audio for story %d: %v", storyID, err)
		return fmt.Errorf("%w: audio conversion failed", ErrAudioProcessingFailed)
	}

	// Update database with filename and duration
	filenameOnly := utils.GetStoryFilename(storyID)
	_, err = s.db.ExecContext(ctx,
		"UPDATE stories SET audio_file = ?, duration_seconds = ? WHERE id = ?",
		filenameOnly, duration, storyID)
	if err != nil {
		logger.Error("Failed to update story %d audio reference: %v", storyID, err)
		return fmt.Errorf("%w: failed to update audio reference", ErrDatabaseError)
	}

	logger.Info("Processed audio for story %d: %s (%.2fs)", storyID, filename, duration)
	return nil
}

// validateVoiceExists checks if a voice exists in the database.
func (s *StoryService) validateVoiceExists(ctx context.Context, voiceID int) error {
	var exists bool
	err := s.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM voices WHERE id = ?)", voiceID)
	if err != nil {
		logger.Error("Database error checking voice existence: %v", err)
		return fmt.Errorf("%w: failed to validate voice", ErrDatabaseError)
	}
	if !exists {
		return fmt.Errorf("%w: voice with id %d not found", ErrNotFound, voiceID)
	}
	return nil
}

// extractWeekdays extracts individual weekday booleans from a weekdays map.
// Returns all weekdays as false if the map is empty or nil.
func (s *StoryService) extractWeekdays(weekdays map[string]bool) (monday, tuesday, wednesday, thursday, friday, saturday, sunday bool) {
	if len(weekdays) == 0 {
		return false, false, false, false, false, false, false
	}

	monday = weekdays["monday"]
	tuesday = weekdays["tuesday"]
	wednesday = weekdays["wednesday"]
	thursday = weekdays["thursday"]
	friday = weekdays["friday"]
	saturday = weekdays["saturday"]
	sunday = weekdays["sunday"]

	return
}

// UpdateStatus updates a story's status field.
// Valid statuses: draft, active, expired
func (s *StoryService) UpdateStatus(ctx context.Context, id int, status string) error {
	// Verify story exists
	if _, err := s.GetByID(ctx, id); err != nil {
		return err
	}

	// Validate status
	storyStatus := models.StoryStatus(status)
	if !storyStatus.IsValid() {
		return fmt.Errorf("%w: status must be one of: draft, active, expired", ErrInvalidInput)
	}

	_, err := s.db.ExecContext(ctx, "UPDATE stories SET status = ? WHERE id = ?", status, id)
	if err != nil {
		logger.Error("Database error updating story status %d: %v", id, err)
		return fmt.Errorf("%w: failed to update story status", ErrDatabaseError)
	}

	return nil
}

// handleDatabaseError converts database errors to service-level errors.
func (s *StoryService) handleDatabaseError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		return fmt.Errorf("%w: story already exists", ErrDuplicate)
	case strings.Contains(errStr, "foreign key constraint"):
		return fmt.Errorf("%w: invalid reference to related resource", ErrInvalidInput)
	case strings.Contains(errStr, "Data too long"):
		return fmt.Errorf("%w: one or more fields exceed maximum length", ErrInvalidInput)
	default:
		return fmt.Errorf("%w: database operation failed", ErrDatabaseError)
	}
}
