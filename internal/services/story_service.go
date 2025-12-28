// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

// StoryServiceDeps contains all dependencies for StoryService.
type StoryServiceDeps struct {
	StoryRepo repository.StoryRepository
	VoiceRepo repository.VoiceRepository
	AudioSvc  *audio.Service
	Config    *config.Config
}

// StoryService handles business logic for news story operations.
type StoryService struct {
	storyRepo repository.StoryRepository
	voiceRepo repository.VoiceRepository
	audioSvc  *audio.Service
	config    *config.Config
}

// NewStoryService creates a new story service instance.
func NewStoryService(deps StoryServiceDeps) *StoryService {
	return &StoryService{
		storyRepo: deps.StoryRepo,
		voiceRepo: deps.VoiceRepo,
		audioSvc:  deps.AudioSvc,
		config:    deps.Config,
	}
}

// CreateStoryRequest contains the data needed to create a new story.
type CreateStoryRequest struct {
	Title     string
	Text      string
	VoiceID   *int64
	Status    string
	StartDate string // Date in YYYY-MM-DD format
	EndDate   string // Date in YYYY-MM-DD format
	Weekdays  map[string]bool
	Metadata  *datatypes.JSONMap
}

// UpdateStoryRequest contains the data needed to update an existing story.
type UpdateStoryRequest struct {
	Title     *string
	Text      *string
	VoiceID   *int64
	Status    *string
	StartDate *string // Date in YYYY-MM-DD format
	EndDate   *string // Date in YYYY-MM-DD format
	Weekdays  map[string]bool
	Metadata  *datatypes.JSONMap
}

// Create creates a new story in the database.
func (s *StoryService) Create(ctx context.Context, req *CreateStoryRequest) (*models.Story, error) {
	// Validate voice exists if provided
	if req.VoiceID != nil {
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to validate voice", apperrors.ErrDatabaseError)
		}
		if !exists {
			return nil, fmt.Errorf("%w: voice with id %d not found", apperrors.ErrNotFound, *req.VoiceID)
		}
	}

	// Parse and validate start date
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid start_date format, must be YYYY-MM-DD", apperrors.ErrInvalidInput)
	}

	// Parse and validate end date
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid end_date format, must be YYYY-MM-DD", apperrors.ErrInvalidInput)
	}

	// Validate date range
	if endDate.Before(startDate) {
		return nil, fmt.Errorf("%w: end date cannot be before start date", apperrors.ErrInvalidInput)
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
func (s *StoryService) Update(ctx context.Context, id int64, req *UpdateStoryRequest) (*models.Story, error) {
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
		return nil, fmt.Errorf("%w: no fields to update", apperrors.ErrInvalidInput)
	}

	// Execute update
	if err := s.storyRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, id)
		}
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
			return nil, nil, fmt.Errorf("%w: invalid start_date format, must be YYYY-MM-DD", apperrors.ErrInvalidInput)
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := time.Parse("2006-01-02", *req.EndDate)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid end_date format, must be YYYY-MM-DD", apperrors.ErrInvalidInput)
		}
		endDate = &parsed
	}

	// Validate date range if both dates provided
	if startDate != nil && endDate != nil {
		if endDate.Before(*startDate) {
			return nil, nil, fmt.Errorf("%w: end date cannot be before start date", apperrors.ErrInvalidInput)
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
			return nil, fmt.Errorf("%w: failed to validate voice", apperrors.ErrDatabaseError)
		}
		if !exists {
			return nil, fmt.Errorf("%w: voice with id %d not found", apperrors.ErrNotFound, *req.VoiceID)
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
		updates.Metadata = req.Metadata
		hasUpdates = true
	}

	if !hasUpdates {
		return nil, nil
	}

	return updates, nil
}

// GetByID retrieves a story by its ID.
func (s *StoryService) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	story, err := s.storyRepo.GetByIDWithVoice(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, id)
		}
		logger.Error("Database error fetching story %d: %v", id, err)
		return nil, fmt.Errorf("%w: failed to fetch story", apperrors.ErrDatabaseError)
	}

	return story, nil
}

// Exists reports whether a story with the given ID exists.
func (s *StoryService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("%w: failed to check story existence: %v", apperrors.ErrDatabaseError, err)
	}
	return exists, nil
}

// SoftDelete marks a story as deleted.
func (s *StoryService) SoftDelete(ctx context.Context, id int64) error {
	err := s.storyRepo.SoftDelete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, id)
		}
		logger.Error("Database error deleting story %d: %v", id, err)
		return fmt.Errorf("%w: failed to delete story", apperrors.ErrDatabaseError)
	}

	return nil
}

// Restore reactivates a soft-deleted story.
func (s *StoryService) Restore(ctx context.Context, id int64) error {
	err := s.storyRepo.Restore(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, id)
		}
		logger.Error("Database error restoring story %d: %v", id, err)
		return fmt.Errorf("%w: failed to restore story", apperrors.ErrDatabaseError)
	}

	return nil
}

// ProcessAudio converts an uploaded audio file and associates it with a story.
func (s *StoryService) ProcessAudio(ctx context.Context, storyID int64, tempPath string) error {
	// Process audio with audio service (convert to mono WAV)
	outputPath := utils.StoryPath(s.config, storyID)
	filename, duration, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 1)
	if err != nil {
		logger.Error("Failed to process story audio for story %d: %v", storyID, err)
		return fmt.Errorf("%w: audio conversion failed", apperrors.ErrAudioProcessingFailed)
	}

	// Update database with filename and duration
	filenameOnly := utils.StoryFilename(storyID)
	err = s.storyRepo.UpdateAudio(ctx, storyID, filenameOnly, duration)
	if err != nil {
		// Clean up file on database error
		if rmErr := os.Remove(outputPath); rmErr != nil {
			logger.Error("Failed to remove audio file after database error: %v", rmErr)
		}
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, storyID)
		}
		logger.Error("Failed to update story %d audio reference: %v", storyID, err)
		return fmt.Errorf("%w: failed to update audio reference", apperrors.ErrDatabaseError)
	}

	logger.Info("Processed audio for story %d: %s (%.2fs)", storyID, filename, duration)
	return nil
}

// extractWeekdays converts a weekday map to individual boolean values.
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

// UpdateStatus changes a story's status to draft, active, or expired.
func (s *StoryService) UpdateStatus(ctx context.Context, id int64, status string) error {
	// Validate status
	storyStatus := models.StoryStatus(status)
	if !storyStatus.IsValid() {
		return fmt.Errorf("%w: status must be one of: draft, active, expired", apperrors.ErrInvalidInput)
	}

	err := s.storyRepo.UpdateStatus(ctx, id, status)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%w: story with id %d", apperrors.ErrNotFound, id)
		}
		logger.Error("Database error updating story status %d: %v", id, err)
		return fmt.Errorf("%w: failed to update story status", apperrors.ErrDatabaseError)
	}

	return nil
}

// handleDatabaseError converts database errors to service-level errors.
func (s *StoryService) handleDatabaseError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, repository.ErrNotFound) {
		return apperrors.ErrNotFound
	}
	if errors.Is(err, repository.ErrDuplicateKey) {
		return fmt.Errorf("%w: story already exists", apperrors.ErrDuplicate)
	}
	if errors.Is(err, repository.ErrForeignKeyViolation) {
		return fmt.Errorf("%w: invalid reference to related resource", apperrors.ErrInvalidInput)
	}
	if errors.Is(err, repository.ErrDataTooLong) {
		return fmt.Errorf("%w: one or more fields exceed maximum length", apperrors.ErrDataTooLong)
	}

	return fmt.Errorf("%w: database operation failed", apperrors.ErrDatabaseError)
}

// List retrieves stories with filtering, sorting, and pagination.
func (s *StoryService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Story], error) {
	result, err := s.storyRepo.List(ctx, query)
	if err != nil {
		logger.Error("Database error listing stories: %v", err)
		return nil, fmt.Errorf("%w: failed to list stories", apperrors.ErrDatabaseError)
	}
	return result, nil
}
