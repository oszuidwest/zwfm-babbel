// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceServiceDeps contains all dependencies for StationVoiceService.
type StationVoiceServiceDeps struct {
	TxManager        repository.TxManager
	StationVoiceRepo repository.StationVoiceRepository
	StationRepo      repository.StationRepository
	VoiceRepo        repository.VoiceRepository
	AudioSvc         *audio.Service
	Config           *config.Config
}

// StationVoiceService handles business logic for station-voice relationship operations.
type StationVoiceService struct {
	txManager        repository.TxManager
	stationVoiceRepo repository.StationVoiceRepository
	stationRepo      repository.StationRepository
	voiceRepo        repository.VoiceRepository
	audioSvc         *audio.Service
	config           *config.Config
}

// NewStationVoiceService creates a new station-voice service instance.
func NewStationVoiceService(deps StationVoiceServiceDeps) *StationVoiceService {
	return &StationVoiceService{
		txManager:        deps.TxManager,
		stationVoiceRepo: deps.StationVoiceRepo,
		stationRepo:      deps.StationRepo,
		voiceRepo:        deps.VoiceRepo,
		audioSvc:         deps.AudioSvc,
		config:           deps.Config,
	}
}

// CreateStationVoiceRequest contains the data needed to create a new station-voice relationship.
type CreateStationVoiceRequest struct {
	StationID int64
	VoiceID   int64
	MixPoint  float64
}

// UpdateStationVoiceRequest contains the data needed to update an existing station-voice relationship.
type UpdateStationVoiceRequest struct {
	StationID *int64
	VoiceID   *int64
	MixPoint  *float64
}

// Create creates a new station-voice relationship.
func (s *StationVoiceService) Create(ctx context.Context, req *CreateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Create"

	var result *models.StationVoice

	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Validate station exists
		exists, err := s.stationRepo.Exists(txCtx, req.StationID)
		if err != nil {
			return fmt.Errorf("%s: %w: failed to validate station", op, apperrors.ErrDatabaseError)
		}
		if !exists {
			return fmt.Errorf("%s: %w: station with id %d not found", op, apperrors.ErrNotFound, req.StationID)
		}

		// Validate voice exists
		exists, err = s.voiceRepo.Exists(txCtx, req.VoiceID)
		if err != nil {
			return fmt.Errorf("%s: %w: failed to validate voice", op, apperrors.ErrDatabaseError)
		}
		if !exists {
			return fmt.Errorf("%s: %w: voice with id %d not found", op, apperrors.ErrNotFound, req.VoiceID)
		}

		// Check uniqueness of station-voice combination
		taken, err := s.stationVoiceRepo.IsCombinationTaken(txCtx, req.StationID, req.VoiceID, nil)
		if err != nil {
			return fmt.Errorf("%s: %w: failed to check uniqueness", op, apperrors.ErrDatabaseError)
		}
		if taken {
			return fmt.Errorf("%s: %w: station-voice combination (station_id=%d, voice_id=%d)", op, apperrors.ErrDuplicate, req.StationID, req.VoiceID)
		}

		// Create station-voice relationship
		stationVoice, err := s.stationVoiceRepo.Create(txCtx, req.StationID, req.VoiceID, req.MixPoint)
		if err != nil {
			if errors.Is(err, repository.ErrDuplicateKey) {
				return fmt.Errorf("%s: %w: station-voice combination already exists", op, apperrors.ErrDuplicate)
			}
			logger.Error("Database error creating station-voice: %v", err)
			return fmt.Errorf("%s: %w", op, apperrors.ErrDatabaseError)
		}

		result = stationVoice
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Update updates an existing station-voice relationship.
func (s *StationVoiceService) Update(ctx context.Context, id int64, req *UpdateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Update"

	// Verify station-voice exists and get current values
	current, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, id)
		}
		return nil, fmt.Errorf("%s: %w: failed to fetch station-voice", op, apperrors.ErrDatabaseError)
	}

	// Validate update request
	if err := s.validateUpdateRequest(ctx, id, current, req); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Build updates struct
	updates := &repository.StationVoiceUpdate{
		StationID: req.StationID,
		VoiceID:   req.VoiceID,
		MixPoint:  req.MixPoint,
	}

	// Validate at least one field is being updated
	if req.StationID == nil && req.VoiceID == nil && req.MixPoint == nil {
		return nil, fmt.Errorf("%s: %w: no fields to update", op, apperrors.ErrInvalidInput)
	}

	// Apply updates
	if err := s.stationVoiceRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, id)
		}
		logger.Error("Database error updating station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w", op, apperrors.ErrDatabaseError)
	}

	// Fetch and return the updated station-voice relationship
	return s.stationVoiceRepo.GetByID(ctx, id)
}

// validateStationIDUpdate validates station_id if being updated.
func (s *StationVoiceService) validateStationIDUpdate(ctx context.Context, stationID *int64) error {
	if stationID == nil {
		return nil
	}
	if *stationID <= 0 {
		return fmt.Errorf("%w: station_id must be positive", apperrors.ErrInvalidInput)
	}
	exists, err := s.stationRepo.Exists(ctx, *stationID)
	if err != nil {
		return fmt.Errorf("%w: failed to validate station", apperrors.ErrDatabaseError)
	}
	if !exists {
		return fmt.Errorf("%w: station with id %d not found", apperrors.ErrNotFound, *stationID)
	}
	return nil
}

// validateVoiceIDUpdate validates voice_id if being updated.
func (s *StationVoiceService) validateVoiceIDUpdate(ctx context.Context, voiceID *int64) error {
	if voiceID == nil {
		return nil
	}
	if *voiceID <= 0 {
		return fmt.Errorf("%w: voice_id must be positive", apperrors.ErrInvalidInput)
	}
	exists, err := s.voiceRepo.Exists(ctx, *voiceID)
	if err != nil {
		return fmt.Errorf("%w: failed to validate voice", apperrors.ErrDatabaseError)
	}
	if !exists {
		return fmt.Errorf("%w: voice with id %d not found", apperrors.ErrNotFound, *voiceID)
	}
	return nil
}

// validateMixPointUpdate validates mix_point if being updated.
func (s *StationVoiceService) validateMixPointUpdate(mixPoint *float64) error {
	if mixPoint == nil {
		return nil
	}
	if *mixPoint < 0 || *mixPoint > 300 {
		return fmt.Errorf("%w: mix_point must be between 0 and 300 seconds", apperrors.ErrInvalidInput)
	}
	return nil
}

// validateUpdateRequest validates all fields in an update request.
func (s *StationVoiceService) validateUpdateRequest(ctx context.Context, id int64, current *models.StationVoice, req *UpdateStationVoiceRequest) error {
	if err := s.validateStationIDUpdate(ctx, req.StationID); err != nil {
		return err
	}
	if err := s.validateVoiceIDUpdate(ctx, req.VoiceID); err != nil {
		return err
	}
	if err := s.validateMixPointUpdate(req.MixPoint); err != nil {
		return err
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
			return fmt.Errorf("%w: failed to check uniqueness", apperrors.ErrDatabaseError)
		}
		if taken {
			return fmt.Errorf("%w: station-voice combination (station_id=%d, voice_id=%d)", apperrors.ErrDuplicate, finalStationID, finalVoiceID)
		}
	}
	return nil
}

// GetByID retrieves a station-voice relationship by its ID.
func (s *StationVoiceService) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	const op = "StationVoiceService.GetByID"

	stationVoice, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w: failed to fetch station-voice", op, apperrors.ErrDatabaseError)
	}

	return stationVoice, nil
}

// Delete removes a station-voice relationship and its associated jingle file.
func (s *StationVoiceService) Delete(ctx context.Context, id int64) error {
	const op = "StationVoiceService.Delete"

	// Get jingle file and station/voice IDs before deletion
	stationID, voiceID, audioFile, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d for deletion: %v", id, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, apperrors.ErrDatabaseError)
	}

	// Delete from database
	err = s.stationVoiceRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, id)
		}
		logger.Error("Database error deleting station-voice %d: %v", id, err)
		return fmt.Errorf("%s: %w: failed to delete station-voice", op, apperrors.ErrDatabaseError)
	}

	// Clean up jingle file if it exists
	if audioFile != "" {
		jinglePath := utils.JinglePath(s.config, stationID, voiceID)
		if err := os.Remove(jinglePath); err != nil {
			// Log error but don't fail the deletion - database record is already gone
			logger.Error("Failed to remove jingle file %s after deletion: %v", jinglePath, err)
		} else {
			logger.Info("Removed jingle file for station %d voice %d", stationID, voiceID)
		}
	}

	return nil
}

// ProcessJingle converts an uploaded audio file and associates it with a station-voice relationship.
func (s *StationVoiceService) ProcessJingle(ctx context.Context, stationVoiceID int64, tempPath string) error {
	const op = "StationVoiceService.ProcessJingle"

	// Get station and voice IDs for the relationship
	stationID, voiceID, _, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, stationVoiceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, apperrors.ErrNotFound, stationVoiceID)
		}
		logger.Error("Database error fetching station-voice %d for jingle processing: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, apperrors.ErrDatabaseError)
	}

	// Process jingle with audio service (convert to WAV 48kHz stereo)
	outputPath := utils.JinglePath(s.config, stationID, voiceID)
	filename, _, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 2)
	if err != nil {
		logger.Error("Failed to process jingle audio for station-voice %d: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: jingle conversion failed", op, apperrors.ErrAudioProcessingFailed)
	}

	// Update database with jingle filename only (not full path)
	filenameOnly := utils.JingleFilename(stationID, voiceID)
	err = s.stationVoiceRepo.UpdateAudio(ctx, stationVoiceID, filenameOnly)
	if err != nil {
		// Clean up file on database error
		if rmErr := os.Remove(outputPath); rmErr != nil {
			logger.Error("Failed to remove jingle file after database error: %v", rmErr)
		}
		logger.Error("Failed to update station-voice %d jingle reference: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to update jingle reference", op, apperrors.ErrDatabaseError)
	}

	logger.Info("Processed jingle for station-voice %d: %s", stationVoiceID, filename)
	return nil
}

// List retrieves a paginated list of station-voice relationships.
func (s *StationVoiceService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.StationVoice], error) {
	const op = "StationVoiceService.List"

	result, err := s.stationVoiceRepo.List(ctx, query)
	if err != nil {
		logger.Error("Database error listing station-voices: %v", err)
		return nil, fmt.Errorf("%s: %w", op, apperrors.ErrDatabaseError)
	}

	return result, nil
}
