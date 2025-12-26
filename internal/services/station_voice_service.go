// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceService handles business logic for station-voice relationship operations.
// It manages the many-to-many relationship between stations and voices, including
// jingle audio file processing and validation.
type StationVoiceService struct {
	stationVoiceRepo repository.StationVoiceRepository
	stationRepo      repository.StationRepository
	voiceRepo        repository.VoiceRepository
	audioSvc         *audio.Service
	config           *config.Config
}

// NewStationVoiceService creates a new station-voice service instance.
func NewStationVoiceService(
	stationVoiceRepo repository.StationVoiceRepository,
	stationRepo repository.StationRepository,
	voiceRepo repository.VoiceRepository,
	audioSvc *audio.Service,
	cfg *config.Config,
) *StationVoiceService {
	return &StationVoiceService{
		stationVoiceRepo: stationVoiceRepo,
		stationRepo:      stationRepo,
		voiceRepo:        voiceRepo,
		audioSvc:         audioSvc,
		config:           cfg,
	}
}

// CreateStationVoiceRequest contains the data needed to create a new station-voice relationship.
type CreateStationVoiceRequest struct {
	StationID int
	VoiceID   int
	MixPoint  float64
}

// UpdateStationVoiceRequest contains the data needed to update an existing station-voice relationship.
type UpdateStationVoiceRequest struct {
	StationID *int
	VoiceID   *int
	MixPoint  *float64
}

// Create creates a new station-voice relationship in the database.
// It validates that both station and voice exist and that the combination is unique.
func (s *StationVoiceService) Create(ctx context.Context, req *CreateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Create"

	// Validate station exists
	exists, err := s.stationRepo.Exists(ctx, req.StationID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: failed to validate station", op, ErrDatabaseError)
	}
	if !exists {
		return nil, fmt.Errorf("%s: %w: station with id %d not found", op, ErrNotFound, req.StationID)
	}

	// Validate voice exists
	exists, err = s.voiceRepo.Exists(ctx, req.VoiceID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: failed to validate voice", op, ErrDatabaseError)
	}
	if !exists {
		return nil, fmt.Errorf("%s: %w: voice with id %d not found", op, ErrNotFound, req.VoiceID)
	}

	// Check uniqueness of station-voice combination
	taken, err := s.stationVoiceRepo.IsCombinationTaken(ctx, req.StationID, req.VoiceID, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: failed to check uniqueness", op, ErrDatabaseError)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: station-voice combination (station_id=%d, voice_id=%d)", op, ErrDuplicate, req.StationID, req.VoiceID)
	}

	// Create station-voice relationship
	stationVoice, err := s.stationVoiceRepo.Create(ctx, req.StationID, req.VoiceID, req.MixPoint)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: station-voice combination already exists", op, ErrDuplicate)
		}
		logger.Error("Database error creating station-voice: %v", err)
		return nil, fmt.Errorf("%s: %w", op, ErrDatabaseError)
	}

	return stationVoice, nil
}

// Update updates an existing station-voice relationship.
// It validates that the station and voice exist (if being updated) and ensures
// the new combination remains unique.
func (s *StationVoiceService) Update(ctx context.Context, id int, req *UpdateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Update"

	// Verify station-voice exists and get current values
	current, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		return nil, fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	// Validate update request
	if err := s.validateUpdateRequest(ctx, id, current, req); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Build updates map
	updates := make(map[string]interface{})
	if req.StationID != nil {
		updates["station_id"] = *req.StationID
	}
	if req.VoiceID != nil {
		updates["voice_id"] = *req.VoiceID
	}
	if req.MixPoint != nil {
		updates["mix_point"] = *req.MixPoint
	}

	if len(updates) == 0 {
		return nil, fmt.Errorf("%s: %w: no fields to update", op, ErrInvalidInput)
	}

	// Apply updates
	if err := s.stationVoiceRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error updating station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w", op, ErrDatabaseError)
	}

	// Fetch and return the updated station-voice relationship
	return s.stationVoiceRepo.GetByID(ctx, id)
}

// validateUpdateRequest validates all fields in an update request.
func (s *StationVoiceService) validateUpdateRequest(ctx context.Context, id int, current *models.StationVoice, req *UpdateStationVoiceRequest) error {
	// Validate station if being updated
	if req.StationID != nil {
		if *req.StationID <= 0 {
			return fmt.Errorf("%w: station_id must be positive", ErrInvalidInput)
		}
		exists, err := s.stationRepo.Exists(ctx, *req.StationID)
		if err != nil {
			return fmt.Errorf("%w: failed to validate station", ErrDatabaseError)
		}
		if !exists {
			return fmt.Errorf("%w: station with id %d not found", ErrNotFound, *req.StationID)
		}
	}

	// Validate voice if being updated
	if req.VoiceID != nil {
		if *req.VoiceID <= 0 {
			return fmt.Errorf("%w: voice_id must be positive", ErrInvalidInput)
		}
		exists, err := s.voiceRepo.Exists(ctx, *req.VoiceID)
		if err != nil {
			return fmt.Errorf("%w: failed to validate voice", ErrDatabaseError)
		}
		if !exists {
			return fmt.Errorf("%w: voice with id %d not found", ErrNotFound, *req.VoiceID)
		}
	}

	// Validate mix_point range if being updated
	if req.MixPoint != nil {
		if *req.MixPoint < 0 || *req.MixPoint > 300 {
			return fmt.Errorf("%w: mix_point must be between 0 and 300 seconds", ErrInvalidInput)
		}
	}

	// Check uniqueness if station_id or voice_id is being updated
	if req.StationID != nil || req.VoiceID != nil {
		finalStationID := current.StationID
		finalVoiceID := current.VoiceID

		if req.StationID != nil {
			finalStationID = *req.StationID
		}
		if req.VoiceID != nil {
			finalVoiceID = *req.VoiceID
		}

		taken, err := s.stationVoiceRepo.IsCombinationTaken(ctx, finalStationID, finalVoiceID, &id)
		if err != nil {
			return fmt.Errorf("%w: failed to check uniqueness", ErrDatabaseError)
		}
		if taken {
			return fmt.Errorf("%w: station-voice combination (station_id=%d, voice_id=%d)", ErrDuplicate, finalStationID, finalVoiceID)
		}
	}

	return nil
}

// GetByID retrieves a station-voice relationship by its ID with joined station and voice names.
func (s *StationVoiceService) GetByID(ctx context.Context, id int) (*models.StationVoice, error) {
	const op = "StationVoiceService.GetByID"

	stationVoice, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	return stationVoice, nil
}

// Delete deletes a station-voice relationship and its associated jingle file if it exists.
// The jingle file is removed from the filesystem after database deletion.
func (s *StationVoiceService) Delete(ctx context.Context, id int) error {
	const op = "StationVoiceService.Delete"

	// Get jingle file and station/voice IDs before deletion
	stationID, voiceID, audioFile, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d for deletion: %v", id, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	// Delete from database
	err = s.stationVoiceRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error deleting station-voice %d: %v", id, err)
		return fmt.Errorf("%s: %w: failed to delete station-voice", op, ErrDatabaseError)
	}

	// Clean up jingle file if it exists
	if audioFile != "" {
		jinglePath := utils.GetJinglePath(s.config, stationID, voiceID)
		if err := os.Remove(jinglePath); err != nil {
			// Log error but don't fail the deletion - database record is already gone
			logger.Error("Failed to remove jingle file %s after deletion: %v", jinglePath, err)
		} else {
			logger.Info("Removed jingle file for station %d voice %d", stationID, voiceID)
		}
	}

	return nil
}

// ProcessJingle processes an uploaded jingle audio file for a station-voice relationship.
// The tempPath should be a validated temporary file path from ValidateAndSaveAudioFile.
// This method converts the audio to standardized WAV format (48kHz stereo) and updates the database.
func (s *StationVoiceService) ProcessJingle(ctx context.Context, stationVoiceID int, tempPath string) error {
	const op = "StationVoiceService.ProcessJingle"

	// Get station and voice IDs for the relationship
	stationID, voiceID, _, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, stationVoiceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, stationVoiceID)
		}
		logger.Error("Database error fetching station-voice %d for jingle processing: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	// Process jingle with audio service (convert to WAV 48kHz stereo)
	outputPath := utils.GetJinglePath(s.config, stationID, voiceID)
	filename, _, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 2)
	if err != nil {
		logger.Error("Failed to process jingle audio for station-voice %d: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: jingle conversion failed", op, ErrAudioProcessingFailed)
	}

	// Update database with jingle filename only (not full path)
	filenameOnly := utils.GetJingleFilename(stationID, voiceID)
	err = s.stationVoiceRepo.UpdateAudio(ctx, stationVoiceID, filenameOnly)
	if err != nil {
		// Clean up file on database error
		if rmErr := os.Remove(outputPath); rmErr != nil {
			logger.Error("Failed to remove jingle file after database error: %v", rmErr)
		}
		logger.Error("Failed to update station-voice %d jingle reference: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to update jingle reference", op, ErrDatabaseError)
	}

	logger.Info("Processed jingle for station-voice %d: %s", stationVoiceID, filename)
	return nil
}

// CheckUniqueness checks if a station-voice combination is unique.
// The excludeID parameter can be provided to exclude a specific record from the check (for updates).
// Returns ErrDuplicate if the combination already exists.
func (s *StationVoiceService) CheckUniqueness(ctx context.Context, stationID, voiceID int, excludeID *int) error {
	const op = "StationVoiceService.CheckUniqueness"

	taken, err := s.stationVoiceRepo.IsCombinationTaken(ctx, stationID, voiceID, excludeID)
	if err != nil {
		logger.Error("Database error checking station-voice uniqueness: %v", err)
		return fmt.Errorf("%s: %w: failed to check uniqueness", op, ErrDatabaseError)
	}

	if taken {
		return fmt.Errorf("%s: %w: station-voice combination (station_id=%d, voice_id=%d)", op, ErrDuplicate, stationID, voiceID)
	}

	return nil
}

// DB returns the underlying database for ModernListWithQuery.
func (s *StationVoiceService) DB() *sqlx.DB {
	return s.stationVoiceRepo.DB()
}
