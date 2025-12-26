// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryService handles business logic for news story operations.
type StoryService struct {
	storyRepo repository.StoryRepository
	voiceRepo repository.VoiceRepository
	audioSvc  *audio.Service
	config    *config.Config
}

// NewStoryService creates a new story service instance.
func NewStoryService(storyRepo repository.StoryRepository, voiceRepo repository.VoiceRepository, audioSvc *audio.Service, cfg *config.Config) *StoryService {
	return &StoryService{
		storyRepo: storyRepo,
		voiceRepo: voiceRepo,
		audioSvc:  audioSvc,
		config:    cfg,
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
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to validate voice", ErrDatabaseError)
		}
		if !exists {
			return nil, fmt.Errorf("%w: voice with id %d not found", ErrNotFound, *req.VoiceID)
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

	// Create story data
	data := &repository.StoryCreateData{
		Title:     req.Title,
		Text:      req.Text,
		VoiceID:   req.VoiceID,
		Status:    req.Status,
		StartDate: startDate,
		EndDate:   endDate,
		Monday:    monday,
		Tuesday:   tuesday,
		Wednesday: wednesday,
		Thursday:  thursday,
		Friday:    friday,
		Saturday:  saturday,
		Sunday:    sunday,
		Metadata:  req.Metadata,
	}

	// Create story via repository
	story, err := s.storyRepo.Create(ctx, data)
	if err != nil {
		logger.Error("Database error creating story: %v", err)
		return nil, s.handleDatabaseError(err)
	}

	return story, nil
}

// Update updates an existing story.
func (s *StoryService) Update(ctx context.Context, id int, req *UpdateStoryRequest) (*models.Story, error) {
	// Verify story exists
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if !exists {
		return nil, fmt.Errorf("%w: story with id %d", ErrNotFound, id)
	}

	// Parse and validate dates
	startDate, endDate, err := s.parseDateUpdates(req)
	if err != nil {
		return nil, err
	}

	// Build type-safe update struct with validated data
	updates, err := s.buildUpdateStruct(ctx, req, startDate, endDate)
	if err != nil {
		return nil, err
	}

	if updates == nil {
		return nil, fmt.Errorf("%w: no fields to update", ErrInvalidInput)
	}

	// Execute update
	if err := s.storyRepo.Update(ctx, id, updates); err != nil {
		logger.Error("Database error updating story: %v", err)
		return nil, s.handleDatabaseError(err)
	}

	// Fetch and return the updated story
	return s.GetByID(ctx, id)
}

// parseDateUpdates parses and validates start and end dates from update request.
func (s *StoryService) parseDateUpdates(req *UpdateStoryRequest) (*time.Time, *time.Time, error) {
	var startDate, endDate *time.Time

	if req.StartDate != nil {
		parsed, err := time.Parse("2006-01-02", *req.StartDate)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid start_date format, must be YYYY-MM-DD", ErrInvalidInput)
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := time.Parse("2006-01-02", *req.EndDate)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid end_date format, must be YYYY-MM-DD", ErrInvalidInput)
		}
		endDate = &parsed
	}

	// Validate date range if both dates provided
	if startDate != nil && endDate != nil {
		if endDate.Before(*startDate) {
			return nil, nil, fmt.Errorf("%w: end date cannot be before start date", ErrInvalidInput)
		}
	}

	return startDate, endDate, nil
}

// buildUpdateStruct constructs a type-safe update struct with validated data.
func (s *StoryService) buildUpdateStruct(ctx context.Context, req *UpdateStoryRequest, startDate, endDate *time.Time) (*repository.StoryUpdate, error) {
	updates := &repository.StoryUpdate{}
	hasUpdates := false

	// Apply simple field updates
	if req.Title != nil {
		updates.Title = req.Title
		hasUpdates = true
	}
	if req.Text != nil {
		updates.Text = req.Text
		hasUpdates = true
	}
	if req.Status != nil {
		updates.Status = req.Status
		hasUpdates = true
	}

	// Apply voice update with validation
	if req.VoiceID != nil {
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to validate voice", ErrDatabaseError)
		}
		if !exists {
			return nil, fmt.Errorf("%w: voice with id %d not found", ErrNotFound, *req.VoiceID)
		}
		updates.VoiceID = req.VoiceID
		hasUpdates = true
	}

	// Apply date updates
	if startDate != nil {
		updates.StartDate = startDate
		hasUpdates = true
	}
	if endDate != nil {
		updates.EndDate = endDate
		hasUpdates = true
	}

	// Apply weekdays updates
	if len(req.Weekdays) > 0 {
		monday, tuesday, wednesday, thursday, friday, saturday, sunday := s.extractWeekdays(req.Weekdays)
		updates.Monday = &monday
		updates.Tuesday = &tuesday
		updates.Wednesday = &wednesday
		updates.Thursday = &thursday
		updates.Friday = &friday
		updates.Saturday = &saturday
		updates.Sunday = &sunday
		hasUpdates = true
	}

	// Apply metadata updates
	if req.Metadata != nil {
		var metadataStr string
		if len(req.Metadata) == 0 {
			// Empty map means clear the metadata (set to NULL in DB)
			updates.Metadata = &metadataStr // Empty string will be stored as NULL
		} else {
			// Marshal to JSON string
			jsonBytes, err := json.Marshal(req.Metadata)
			if err != nil {
				return nil, fmt.Errorf("%w: failed to marshal metadata", ErrInvalidInput)
			}
			metadataStr = string(jsonBytes)
			updates.Metadata = &metadataStr
		}
		hasUpdates = true
	}

	if !hasUpdates {
		return nil, nil
	}

	return updates, nil
}

// GetByID retrieves a story by its ID.
func (s *StoryService) GetByID(ctx context.Context, id int) (*models.Story, error) {
	story, err := s.storyRepo.GetByIDWithVoice(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: story with id %d", ErrNotFound, id)
		}
		logger.Error("Database error fetching story %d: %v", id, err)
		return nil, fmt.Errorf("%w: failed to fetch story", ErrDatabaseError)
	}

	return story, nil
}

// SoftDelete marks a story as deleted by setting the deleted_at timestamp.
func (s *StoryService) SoftDelete(ctx context.Context, id int) error {
	// Verify story exists
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
	}

	err = s.storyRepo.SoftDelete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
		}
		logger.Error("Database error deleting story %d: %v", id, err)
		return fmt.Errorf("%w: failed to delete story", ErrDatabaseError)
	}

	return nil
}

// Restore restores a soft-deleted story by clearing the deleted_at timestamp.
func (s *StoryService) Restore(ctx context.Context, id int) error {
	// Verify story exists (even if deleted)
	exists, err := s.storyRepo.ExistsIncludingDeleted(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
	}

	err = s.storyRepo.Restore(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
		}
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
	exists, err := s.storyRepo.Exists(ctx, storyID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%w: story with id %d", ErrNotFound, storyID)
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
	err = s.storyRepo.UpdateAudio(ctx, storyID, filenameOnly, duration)
	if err != nil {
		logger.Error("Failed to update story %d audio reference: %v", storyID, err)
		return fmt.Errorf("%w: failed to update audio reference", ErrDatabaseError)
	}

	logger.Info("Processed audio for story %d: %s (%.2fs)", storyID, filename, duration)
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
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
	}

	// Validate status
	storyStatus := models.StoryStatus(status)
	if !storyStatus.IsValid() {
		return fmt.Errorf("%w: status must be one of: draft, active, expired", ErrInvalidInput)
	}

	err = s.storyRepo.UpdateStatus(ctx, id, status)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", ErrNotFound, id)
		}
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

	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, repository.ErrDuplicateKey) {
		return fmt.Errorf("%w: story already exists", ErrDuplicate)
	}
	if errors.Is(err, repository.ErrForeignKeyViolation) {
		return fmt.Errorf("%w: invalid reference to related resource", ErrInvalidInput)
	}
	if errors.Is(err, repository.ErrDataTooLong) {
		return fmt.Errorf("%w: one or more fields exceed maximum length", ErrInvalidInput)
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

// DB returns the underlying database for ModernListWithQuery.
func (s *StoryService) DB() *sqlx.DB {
	return s.storyRepo.DB()
}
