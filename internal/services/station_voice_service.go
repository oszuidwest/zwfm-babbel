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
	var result *models.StationVoice

	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Validate station exists
		exists, err := s.stationRepo.Exists(txCtx, req.StationID)
		if err != nil {
			return apperrors.Database("StationVoice", "query", err)
		}
		if !exists {
			return apperrors.NotFoundWithID("Station", req.StationID)
		}

		// Validate voice exists
		exists, err = s.voiceRepo.Exists(txCtx, req.VoiceID)
		if err != nil {
			return apperrors.Database("StationVoice", "query", err)
		}
		if !exists {
			return apperrors.NotFoundWithID("Voice", req.VoiceID)
		}

		// Check uniqueness of station-voice combination
		taken, err := s.stationVoiceRepo.IsCombinationTaken(txCtx, req.StationID, req.VoiceID, nil)
		if err != nil {
			return apperrors.Database("StationVoice", "query", err)
		}
		if taken {
			return apperrors.Duplicate("StationVoice", "station_id/voice_id", fmt.Sprintf("%d/%d", req.StationID, req.VoiceID))
		}

		// Create station-voice relationship
		stationVoice, err := s.stationVoiceRepo.Create(txCtx, req.StationID, req.VoiceID, req.MixPoint)
		if err != nil {
			if errors.Is(err, repository.ErrDuplicateKey) {
				return apperrors.Duplicate("StationVoice", "combination", "")
			}
			return apperrors.Database("StationVoice", "create", err)
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
	// Verify station-voice exists and get current values
	current, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperrors.NotFoundWithID("StationVoice", id)
		}
		return nil, apperrors.Database("StationVoice", "query", err)
	}

	// Validate update request
	if err := s.validateUpdateRequest(ctx, id, current, req); err != nil {
		return nil, err
	}

	// Build updates struct
	updates := &repository.StationVoiceUpdate{
		StationID: req.StationID,
		VoiceID:   req.VoiceID,
		MixPoint:  req.MixPoint,
	}

	// Validate at least one field is being updated
	if req.StationID == nil && req.VoiceID == nil && req.MixPoint == nil {
		return nil, apperrors.Validation("StationVoice", "", "no fields to update")
	}

	// Apply updates
	if err := s.stationVoiceRepo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperrors.NotFoundWithID("StationVoice", id)
		}
		return nil, apperrors.Database("StationVoice", "update", err)
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
		return apperrors.Validation("StationVoice", "station_id", "must be positive")
	}
	exists, err := s.stationRepo.Exists(ctx, *stationID)
	if err != nil {
		return apperrors.Database("StationVoice", "query", err)
	}
	if !exists {
		return apperrors.NotFoundWithID("Station", *stationID)
	}
	return nil
}

// validateVoiceIDUpdate validates voice_id if being updated.
func (s *StationVoiceService) validateVoiceIDUpdate(ctx context.Context, voiceID *int64) error {
	if voiceID == nil {
		return nil
	}
	if *voiceID <= 0 {
		return apperrors.Validation("StationVoice", "voice_id", "must be positive")
	}
	exists, err := s.voiceRepo.Exists(ctx, *voiceID)
	if err != nil {
		return apperrors.Database("StationVoice", "query", err)
	}
	if !exists {
		return apperrors.NotFoundWithID("Voice", *voiceID)
	}
	return nil
}

// validateMixPointUpdate validates mix_point if being updated.
func (s *StationVoiceService) validateMixPointUpdate(mixPoint *float64) error {
	if mixPoint == nil {
		return nil
	}
	if *mixPoint < 0 || *mixPoint > 300 {
		return apperrors.Validation("StationVoice", "mix_point", "must be between 0 and 300 seconds")
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
			return apperrors.Database("StationVoice", "query", err)
		}
		if taken {
			return apperrors.Duplicate("StationVoice", "station_id/voice_id", fmt.Sprintf("%d/%d", finalStationID, finalVoiceID))
		}
	}
	return nil
}

// GetByID retrieves a station-voice relationship by its ID.
func (s *StationVoiceService) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	stationVoice, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apperrors.NotFoundWithID("StationVoice", id)
		}
		return nil, apperrors.Database("StationVoice", "query", err)
	}

	return stationVoice, nil
}

// Delete removes a station-voice relationship and its associated jingle file.
func (s *StationVoiceService) Delete(ctx context.Context, id int64) error {
	// Get jingle file and station/voice IDs before deletion
	stationID, voiceID, audioFile, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("StationVoice", id)
		}
		return apperrors.Database("StationVoice", "query", err)
	}

	// Delete from database
	err = s.stationVoiceRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("StationVoice", id)
		}
		return apperrors.Database("StationVoice", "delete", err)
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
	// Get station and voice IDs for the relationship
	stationID, voiceID, _, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, stationVoiceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return apperrors.NotFoundWithID("StationVoice", stationVoiceID)
		}
		return apperrors.Database("StationVoice", "query", err)
	}

	// Process jingle with audio service (convert to WAV 48kHz stereo)
	outputPath := utils.JinglePath(s.config, stationID, voiceID)
	filename, _, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 2)
	if err != nil {
		return apperrors.Audio("StationVoice", "convert", err)
	}

	// Update database with jingle filename only (not full path)
	filenameOnly := utils.JingleFilename(stationID, voiceID)
	err = s.stationVoiceRepo.UpdateAudio(ctx, stationVoiceID, filenameOnly)
	if err != nil {
		// Clean up file on database error
		if rmErr := os.Remove(outputPath); rmErr != nil {
			logger.Error("Failed to remove jingle file after database error: %v", rmErr)
		}
		return apperrors.Database("StationVoice", "update", err)
	}

	logger.Info("Processed jingle for station-voice %d: %s", stationVoiceID, filename)
	return nil
}

// List retrieves a paginated list of station-voice relationships.
func (s *StationVoiceService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.StationVoice], error) {
	result, err := s.stationVoiceRepo.List(ctx, query)
	if err != nil {
		return nil, apperrors.Database("StationVoice", "query", err)
	}

	return result, nil
}
