// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"net/http"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/datatypes"
)

// StoryServiceDeps contains all dependencies for StoryService.
type StoryServiceDeps struct {
	StoryRepo repository.StoryRepository
	VoiceRepo repository.VoiceRepository
	AudioSvc  *audio.Service
	TTSSvc    *tts.Service
	Config    *config.Config
}

// StoryService handles business logic for news story operations.
type StoryService struct {
	storyRepo repository.StoryRepository
	voiceRepo repository.VoiceRepository
	audioSvc  *audio.Service
	ttsSvc    *tts.Service
	config    *config.Config
}

// NewStoryService creates a new story service instance.
func NewStoryService(deps StoryServiceDeps) *StoryService {
	return &StoryService{
		storyRepo: deps.StoryRepo,
		voiceRepo: deps.VoiceRepo,
		audioSvc:  deps.AudioSvc,
		ttsSvc:    deps.TTSSvc,
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
	Weekdays  models.Weekdays
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
	Weekdays  *models.Weekdays
	Metadata  *datatypes.JSONMap
}

// Create creates a new story in the database.
func (s *StoryService) Create(ctx context.Context, req *CreateStoryRequest) (*models.Story, error) {
	// Validate voice exists if provided
	if req.VoiceID != nil {
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return nil, apperrors.Database("Story", "query", err)
		}
		if !exists {
			return nil, apperrors.NotFoundWithID("Voice", *req.VoiceID)
		}
	}

	// Parse and validate start date (using local timezone for consistent date handling)
	startDate, err := time.ParseInLocation("2006-01-02", req.StartDate, time.Local)
	if err != nil {
		return nil, apperrors.Validation("Story", "start_date", "invalid format, must be YYYY-MM-DD")
	}

	// Parse and validate end date (using local timezone for consistent date handling)
	endDate, err := time.ParseInLocation("2006-01-02", req.EndDate, time.Local)
	if err != nil {
		return nil, apperrors.Validation("Story", "end_date", "invalid format, must be YYYY-MM-DD")
	}

	// Validate date range
	if endDate.Before(startDate) {
		return nil, apperrors.Validation("Story", "end_date", "cannot be before start date")
	}

	// Create story data
	data := &repository.StoryCreateData{
		Title:     req.Title,
		Text:      req.Text,
		VoiceID:   req.VoiceID,
		Status:    req.Status,
		StartDate: startDate,
		EndDate:   endDate,
		Weekdays:  req.Weekdays,
		Metadata:  req.Metadata,
	}

	// Create story via repository
	story, err := s.storyRepo.Create(ctx, data)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpCreate, err)
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

	// For partial date updates, validate against existing story dates
	// XOR: exactly one date is provided (not both, not neither)
	if (startDate != nil) != (endDate != nil) {
		existing, err := s.storyRepo.GetByID(ctx, id)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return nil, apperrors.NotFoundWithID("Story", id)
			}
			return nil, apperrors.Database("Story", "query", err)
		}

		effectiveStart := existing.StartDate
		effectiveEnd := existing.EndDate
		if startDate != nil {
			effectiveStart = *startDate
		}
		if endDate != nil {
			effectiveEnd = *endDate
		}

		if effectiveEnd.Before(effectiveStart) {
			return nil, apperrors.Validation("Story", "end_date", "cannot be before start date")
		}
	}

	// Build type-safe update struct with validated data
	updates, err := s.buildUpdateStruct(ctx, req, startDate, endDate)
	if err != nil {
		return nil, err
	}

	if updates == nil {
		return nil, apperrors.Validation("Story", "", "no fields to update")
	}

	// Execute update
	if err := s.storyRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperrors.NotFoundWithID("Story", id)
		}
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpUpdate, err)
	}

	// Fetch and return the updated story
	return s.GetByID(ctx, id)
}

// parseDateUpdates parses and validates start and end dates from update request.
func (s *StoryService) parseDateUpdates(req *UpdateStoryRequest) (*time.Time, *time.Time, error) {
	var startDate, endDate *time.Time

	if req.StartDate != nil {
		parsed, err := time.ParseInLocation("2006-01-02", *req.StartDate, time.Local)
		if err != nil {
			return nil, nil, apperrors.Validation("Story", "start_date", "invalid format, must be YYYY-MM-DD")
		}
		startDate = &parsed
	}

	if req.EndDate != nil {
		parsed, err := time.ParseInLocation("2006-01-02", *req.EndDate, time.Local)
		if err != nil {
			return nil, nil, apperrors.Validation("Story", "end_date", "invalid format, must be YYYY-MM-DD")
		}
		endDate = &parsed
	}

	// Validate date range if both dates provided
	if startDate != nil && endDate != nil {
		if endDate.Before(*startDate) {
			return nil, nil, apperrors.Validation("Story", "end_date", "cannot be before start date")
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
			return nil, apperrors.Database("Story", "query", err)
		}
		if !exists {
			return nil, apperrors.NotFoundWithID("Voice", *req.VoiceID)
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
	if req.Weekdays != nil {
		updates.Weekdays = req.Weekdays
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
			return nil, apperrors.NotFoundWithID("Story", id)
		}
		return nil, apperrors.Database("Story", "query", err)
	}

	return story, nil
}

// Exists reports whether a story with the given ID exists.
func (s *StoryService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.storyRepo.Exists(ctx, id)
	if err != nil {
		return false, apperrors.Database("Story", "query", err)
	}
	return exists, nil
}

// SoftDelete marks a story as deleted.
func (s *StoryService) SoftDelete(ctx context.Context, id int64) error {
	err := s.storyRepo.SoftDelete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("Story", id)
		}
		return apperrors.Database("Story", "delete", err)
	}

	return nil
}

// Restore reactivates a soft-deleted story.
func (s *StoryService) Restore(ctx context.Context, id int64) error {
	err := s.storyRepo.Restore(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("Story", id)
		}
		return apperrors.Database("Story", "update", err)
	}

	return nil
}

// ProcessAudio converts an uploaded audio file and associates it with a story.
func (s *StoryService) ProcessAudio(ctx context.Context, storyID int64, tempPath string) error {
	// Process audio with audio service (convert to mono WAV)
	outputPath := utils.StoryPath(s.config, storyID)
	filename, duration, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 1)
	if err != nil {
		return apperrors.Audio("Story", "convert", err)
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
			return apperrors.NotFoundWithID("Story", storyID)
		}
		return apperrors.Database("Story", "update", err)
	}

	logger.Info("Processed audio for story %d: %s (%.2fs)", storyID, filename, duration)
	return nil
}

// UpdateStatus changes a story's status to draft, active, or expired.
// Returns the updated story.
func (s *StoryService) UpdateStatus(ctx context.Context, id int64, status string) (*models.Story, error) {
	// Validate status
	storyStatus := models.StoryStatus(status)
	if !storyStatus.IsValid() {
		return nil, apperrors.Validation("Story", "status", "must be one of: draft, active, expired")
	}

	err := s.storyRepo.UpdateStatus(ctx, id, status)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperrors.NotFoundWithID("Story", id)
		}
		return nil, apperrors.Database("Story", "update", err)
	}

	return s.GetByID(ctx, id)
}

// List retrieves stories with filtering, sorting, and pagination.
func (s *StoryService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Story], error) {
	result, err := s.storyRepo.List(ctx, query)
	if err != nil {
		return nil, apperrors.Database("Story", "query", err)
	}
	return result, nil
}

// GenerateTTS generates audio for a story using text-to-speech.
// If the story already has audio, pass force=true to overwrite it.
func (s *StoryService) GenerateTTS(ctx context.Context, storyID int64, force bool) error {
	story, err := s.storyRepo.GetByID(ctx, storyID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("Story", storyID)
		}
		return apperrors.Database("Story", "query", err)
	}

	// Validate TTS prerequisites
	if story.AudioFile != "" && !force {
		return apperrors.Validation("Story", "audio_file", "story already has audio — use ?force=true to overwrite")
	}
	if story.Text == "" {
		return apperrors.Validation("Story", "text", "story has no text for TTS generation")
	}
	if story.VoiceID == nil {
		return apperrors.Validation("Story", "voice_id", "story has no voice assigned for TTS generation")
	}
	if story.Voice == nil || story.Voice.ElevenLabsVoiceID == nil || *story.Voice.ElevenLabsVoiceID == "" {
		return apperrors.Validation("Voice", "elevenlabs_voice_id", "voice has no ElevenLabs voice ID configured")
	}

	// Generate speech via TTS service
	audioData, err := s.ttsSvc.GenerateSpeech(ctx, story.Text, *story.Voice.ElevenLabsVoiceID)
	if err != nil {
		return translateTTSError(err)
	}

	// Write to temp file for processing through the standard audio pipeline
	tempPath, err := writeTempFile(audioData, fmt.Sprintf("tts_story_%d_*.mp3", storyID))
	if err != nil {
		return apperrors.Audio("Story", "tts_write_temp", err)
	}
	defer func() {
		if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
			logger.Warn("Failed to remove TTS temp file %s: %v", tempPath, err)
		}
	}()

	return s.ProcessAudio(ctx, storyID, tempPath)
}

// translateTTSError maps TTS service errors to domain errors with specific messages.
func translateTTSError(err error) error {
	if apiErr, ok := errors.AsType[*tts.APIError](err); ok {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return apperrors.Validation("TTS", "api_key", apiErr.Error())
		case http.StatusNotFound:
			return apperrors.Validation("Voice", "elevenlabs_voice_id", apiErr.Error())
		case http.StatusTooManyRequests:
			return apperrors.Validation("TTS", "rate_limit", apiErr.Error())
		}
	}
	return apperrors.Audio("Story", "tts_generate", err)
}

// writeTempFile creates a temporary file with the given data and pattern, returning its path.
func writeTempFile(data []byte, pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}

	path := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}

	return path, nil
}
