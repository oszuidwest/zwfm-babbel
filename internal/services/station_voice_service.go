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

// StationVoiceServiceDeps groups the collaborators required to validate and
// mutate station-voice relationships.
type StationVoiceServiceDeps struct {
	TxManager        repository.TxManager
	StationVoiceRepo *repository.StationVoiceRepository
	StationRepo      *repository.StationRepository
	VoiceRepo        *repository.VoiceRepository
	AudioSvc         *audio.Service
	Config           *config.Config
}

type stationVoiceRepository interface {
	Create(context.Context, int64, int64, float64) (*models.StationVoice, error)
	GetByID(context.Context, int64) (*models.StationVoice, error)
	GetForUpdate(context.Context, int64) (*models.StationVoice, error)
	Update(context.Context, int64, *repository.StationVoiceUpdate) error
	IsCombinationTaken(context.Context, int64, int64, *int64) (bool, error)
	GetStationVoiceIDs(context.Context, int64) (int64, int64, string, error)
	Delete(context.Context, int64) error
	UpdateAudio(context.Context, int64, string) error
	List(context.Context, *repository.ListQuery) (*repository.ListResult[models.StationVoice], error)
}

// StationVoiceService manages station-voice relationships and their jingle
// files as one domain boundary.
type StationVoiceService struct {
	txManager        repository.TxManager
	stationVoiceRepo stationVoiceRepository
	stationRepo      *repository.StationRepository
	voiceRepo        *repository.VoiceRepository
	audioSvc         *audio.Service
	config           *config.Config
}

// NewStationVoiceService returns a station-voice service wired to deps.
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

// CreateStationVoiceRequest identifies the station, voice, and mix point for a
// new station-voice relationship.
type CreateStationVoiceRequest struct {
	StationID int64
	VoiceID   int64
	MixPoint  float64
}

// UpdateStationVoiceRequest carries PATCH-style station-voice fields.
// Nil pointers leave the corresponding field unchanged.
type UpdateStationVoiceRequest struct {
	StationID *int64
	VoiceID   *int64
	MixPoint  *float64
}

// Create inserts a relationship after validating both parents and uniqueness in
// a single transaction.
func (s *StationVoiceService) Create(ctx context.Context, req *CreateStationVoiceRequest) (*models.StationVoice, error) {
	var result *models.StationVoice

	err := inTransaction(ctx, s.txManager, "StationVoice", apperrors.OpCreate, func(txCtx context.Context) error {
		if err := requireReference(txCtx, s.stationRepo.Exists, "StationVoice", "station_id", req.StationID); err != nil {
			return err
		}
		if err := requireReference(txCtx, s.voiceRepo.Exists, "StationVoice", "voice_id", req.VoiceID); err != nil {
			return err
		}

		taken, err := s.stationVoiceRepo.IsCombinationTaken(txCtx, req.StationID, req.VoiceID, nil)
		if err != nil {
			return apperrors.TranslateRepoError("StationVoice", apperrors.OpQuery, err)
		}
		if taken {
			return apperrors.Duplicate("StationVoice", "station_id/voice_id", fmt.Sprintf("%d/%d", req.StationID, req.VoiceID))
		}

		stationVoice, err := s.stationVoiceRepo.Create(txCtx, req.StationID, req.VoiceID, req.MixPoint)
		if err != nil {
			if errors.Is(err, repository.ErrDuplicateKey) {
				return apperrors.Duplicate("StationVoice", "combination", "")
			}
			return apperrors.TranslateRepoError("StationVoice", apperrors.OpCreate, err)
		}

		result = stationVoice
		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Update applies relationship changes while preserving the uniqueness of the
// final station/voice pair. The jingle file is named after the pair, so the
// station and voice cannot change once a jingle exists.
func (s *StationVoiceService) Update(ctx context.Context, id int64, req *UpdateStationVoiceRequest) (*models.StationVoice, error) {
	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// The row lock makes a jingle write that has not committed yet finish
		// first, so the check sees it. An upload that loaded the pair before
		// this commit still writes that pair's filename afterwards.
		current, err := s.stationVoiceRepo.GetForUpdate(txCtx, id)
		if err != nil {
			return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpQuery, err)
		}
		// No pair change can succeed on this row, so report that before
		// validating the new pair.
		if current.AudioFile != "" && changesPair(current, req) {
			return apperrors.Conflict("stationvoice.jingle_locked",
				"station_id and voice_id cannot change while the station-voice has a jingle",
				"Create a station-voice for the new station and voice, upload its jingle, then delete this one")
		}
		if err := s.validateUpdateRequest(txCtx, id, current, req); err != nil {
			return err
		}
		updates := &repository.StationVoiceUpdate{
			StationID: req.StationID,
			VoiceID:   req.VoiceID,
			MixPoint:  req.MixPoint,
		}
		if err := s.stationVoiceRepo.Update(txCtx, id, updates); err != nil {
			return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpUpdate, err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return s.GetByID(ctx, id)
}

// changesPair reports whether req moves stationVoice to another station or voice.
func changesPair(stationVoice *models.StationVoice, req *UpdateStationVoiceRequest) bool {
	return (req.StationID != nil && *req.StationID != stationVoice.StationID) ||
		(req.VoiceID != nil && *req.VoiceID != stationVoice.VoiceID)
}

// validateUpdateRequest checks that changed parents exist and that the final
// station/voice pair stays unique. Binding enforces ID and mix_point ranges.
func (s *StationVoiceService) validateUpdateRequest(ctx context.Context, id int64, current *models.StationVoice, req *UpdateStationVoiceRequest) error {
	if req.StationID != nil {
		if err := requireReference(ctx, s.stationRepo.Exists, "StationVoice", "station_id", *req.StationID); err != nil {
			return err
		}
	}
	if req.VoiceID != nil {
		if err := requireReference(ctx, s.voiceRepo.Exists, "StationVoice", "voice_id", *req.VoiceID); err != nil {
			return err
		}
	}

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
			return apperrors.TranslateRepoError("StationVoice", apperrors.OpQuery, err)
		}
		if taken {
			return apperrors.Duplicate("StationVoice", "station_id/voice_id", fmt.Sprintf("%d/%d", finalStationID, finalVoiceID))
		}
	}
	return nil
}

// GetByID loads a station-voice relationship and maps repository misses to a
// domain not-found error.
func (s *StationVoiceService) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	stationVoice, err := s.stationVoiceRepo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpQuery, err)
	}

	return stationVoice, nil
}

// Delete removes a relationship and its canonical jingle file, even when the
// row recorded none, because a first upload may have committed after the row
// was read. The file is removed before commit, while the uncommitted delete
// still blocks a replacement for the same pair, so the cleanup cannot remove
// the replacement's jingle. A file that cannot be removed rolls the delete
// back, so a recreated pair never picks up the stale jingle. A failed commit
// can keep the row without its jingle; bulletins then play without a bed until
// a new upload.
func (s *StationVoiceService) Delete(ctx context.Context, id int64) error {
	stationID, voiceID, _, err := s.stationVoiceRepo.GetStationVoiceIDs(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpQuery, err)
	}

	return s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := s.stationVoiceRepo.Delete(txCtx, id); err != nil {
			return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpDelete, err)
		}

		jinglePath := utils.JinglePath(s.config, stationID, voiceID)
		if err := os.Remove(jinglePath); err == nil {
			logger.Info("Removed jingle file", "station_voice_id", id, "station_id", stationID, "voice_id", voiceID)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove jingle %s of station-voice %d: %w", jinglePath, id, err)
		}
		return nil
	})
}

// ProcessJingle converts an uploaded audio file and associates it with the
// already-loaded station-voice relationship. The database stores the
// canonical filename, not the absolute output path.
func (s *StationVoiceService) ProcessJingle(ctx context.Context, stationVoice *models.StationVoice, tempPath string) error {
	outputPath := utils.JinglePath(s.config, stationVoice.StationID, stationVoice.VoiceID)
	convertedPath, cleanup, err := utils.ProcessingPath(outputPath,
		fmt.Sprintf("station_%d_voice_%d", stationVoice.StationID, stationVoice.VoiceID))
	if err != nil {
		return apperrors.Audio("StationVoice", "convert", err)
	}
	defer cleanup()
	filename := utils.JingleFilename(stationVoice.StationID, stationVoice.VoiceID)

	if err := s.audioSvc.ConvertJingleToWAV(ctx, tempPath, convertedPath); err != nil {
		return apperrors.Audio("StationVoice", "convert", err)
	}

	// Rename while the row update holds the row lock, so a concurrent Delete
	// cannot remove the row and its jingle between the update and the rename.
	// A failed update or rename rolls back and keeps the old jingle; a failed
	// commit leaves the new jingle published and may leave the database
	// outcome unknown.
	published := false
	err = s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := s.stationVoiceRepo.UpdateAudio(txCtx, stationVoice.ID, filename); err != nil {
			return err
		}
		if err := os.Rename(convertedPath, outputPath); err != nil {
			return apperrors.Audio("StationVoice", "finalize", err)
		}
		published = true
		return nil
	})
	if err != nil {
		// A failed rename is already an audio error. Anything else came from
		// the transaction: begin, the row update, or commit.
		if audioErr, ok := errors.AsType[*apperrors.AudioError](err); ok {
			return audioErr
		}
		if published {
			// The handler logs the cause; name the live file there.
			err = fmt.Errorf("station-voice %d jingle published to %s but commit failed: %w", stationVoice.ID, outputPath, err)
		}
		return apperrors.TranslateRepoErrorWithID("StationVoice", stationVoice.ID, apperrors.OpUpdate, err)
	}

	logger.Info("Processed jingle for station-voice", "station_voice_id", stationVoice.ID, "filename", outputPath)
	return nil
}

// List retrieves a paginated list of station-voice relationships.
func (s *StationVoiceService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.StationVoice], error) {
	result, err := s.stationVoiceRepo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("StationVoice", apperrors.OpQuery, err)
	}

	return result, nil
}
