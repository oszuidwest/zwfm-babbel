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
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
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
	Alerts           notify.Alerter
}

type stationVoiceRepository interface {
	Create(context.Context, int64, int64, float64) (*models.StationVoice, error)
	GetByID(context.Context, int64) (*models.StationVoice, error)
	GetForUpdate(context.Context, int64) (*models.StationVoice, error)
	Update(context.Context, int64, *repository.StationVoiceUpdate) error
	IsCombinationTaken(context.Context, int64, int64, *int64) (bool, error)
	IsJingleInUse(context.Context, string, int64, int64) (bool, error)
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
	alerts           notify.Alerter
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
		alerts:           notify.OrDiscard(deps.Alerts),
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
		// this commit finds the pair changed and is refused.
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

// Delete removes a relationship and its jingle files. The row is locked before
// it is read, so a pair change or upload either commits first and is seen, or
// waits for the delete. The canonical file of the locked pair is removed even
// when the row recorded none, because an upload whose commit failed can leave
// it published. A row can also store a jingle named after an earlier pair;
// that file is removed too unless a remaining row stores it or owns that pair.
// Files are removed before commit, while the uncommitted delete still blocks a
// replacement for the same pair, so the cleanup cannot remove the
// replacement's jingle. A file that cannot be removed rolls the delete back, so
// a recreated pair never picks up the stale jingle. A failed commit can keep
// the row without its jingle; bulletins then play without a bed until a new
// upload.
func (s *StationVoiceService) Delete(ctx context.Context, id int64) error {
	return inTransaction(ctx, s.txManager, "StationVoice", apperrors.OpDelete, func(txCtx context.Context) error {
		stationVoice, err := s.stationVoiceRepo.GetForUpdate(txCtx, id)
		if err != nil {
			return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpQuery, err)
		}
		if err := s.stationVoiceRepo.Delete(txCtx, id); err != nil {
			return apperrors.TranslateRepoErrorWithID("StationVoice", id, apperrors.OpDelete, err)
		}

		if err := s.removeJingle(id, stationVoice.StationID, stationVoice.VoiceID); err != nil {
			return err
		}
		return s.removeStoredJingle(txCtx, stationVoice)
	})
}

// removeStoredJingle removes the jingle a deleted row stores under another
// pair's name, unless a remaining row stores it or owns that pair. A stored
// name that is not a jingle filename is left alone, so nothing outside the
// jingle directory is removed.
func (s *StationVoiceService) removeStoredJingle(ctx context.Context, stationVoice *models.StationVoice) error {
	if stationVoice.AudioFile == "" || stationVoice.AudioFile == utils.JingleFilename(stationVoice.StationID, stationVoice.VoiceID) {
		return nil
	}
	stationID, voiceID, ok := utils.ParseJingleFilename(stationVoice.AudioFile)
	if !ok {
		logger.Warn("Kept stored jingle with an unexpected filename", "station_voice_id", stationVoice.ID, "audio_file", stationVoice.AudioFile)
		return nil
	}
	inUse, err := s.stationVoiceRepo.IsJingleInUse(ctx, stationVoice.AudioFile, stationID, voiceID)
	if err != nil {
		return apperrors.TranslateRepoErrorWithID("StationVoice", stationVoice.ID, apperrors.OpQuery, err)
	}
	if inUse {
		return nil
	}
	return s.removeJingle(stationVoice.ID, stationID, voiceID)
}

// removeJingle removes the jingle named after a station/voice pair on behalf
// of station-voice id. A missing file is not an error.
func (s *StationVoiceService) removeJingle(id, stationID, voiceID int64) error {
	jinglePath := utils.JinglePath(s.config, stationID, voiceID)
	if err := os.Remove(jinglePath); err == nil {
		logger.Info("Removed jingle file", "station_voice_id", id, "station_id", stationID, "voice_id", voiceID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove jingle %s of station-voice %d: %w", jinglePath, id, err)
	}
	return nil
}

// ProcessJingle converts an uploaded audio file and associates it with the
// already-loaded station-voice relationship. It refuses to publish when the
// row moved to another pair since it was loaded, because the file is named
// after the loaded pair. The database stores the canonical filename, not the
// absolute output path.
// Conversion follows ctx; publication ignores request cancellation and has
// its own deadline so a disconnect cannot roll back an already-live jingle.
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
		if errors.Is(err, audio.ErrUndecodable) {
			return undecodableUpload("jingle", err)
		}
		return apperrors.Audio("StationVoice", "convert", err)
	}

	// Check the pair and rename under the row lock, so a concurrent Update
	// cannot move the row and a concurrent Delete cannot remove the row and its
	// jingle before the rename. A failed check, update or rename rolls back and
	// keeps the old jingle; a failed commit leaves the new jingle published and
	// may leave the database outcome unknown.
	publishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), audioPublishTimeout)
	defer cancel()
	alertKey := fmt.Sprintf("stationvoice:unrecorded-audio:%d", stationVoice.ID)
	published := false
	err = s.txManager.WithTransaction(publishCtx, func(txCtx context.Context) error {
		current, err := s.stationVoiceRepo.GetForUpdate(txCtx, stationVoice.ID)
		if err != nil {
			return err
		}
		if current.StationID != stationVoice.StationID || current.VoiceID != stationVoice.VoiceID {
			return apperrors.Conflict("stationvoice.pair_changed",
				"the station-voice moved to another station or voice during the upload",
				"Upload the jingle again")
		}
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
		// A failed rename is already an audio error and a changed pair a
		// conflict. Anything else came from the transaction: begin, the row
		// read or update, or commit.
		if audioErr, ok := errors.AsType[*apperrors.AudioError](err); ok {
			return audioErr
		}
		if conflict, ok := errors.AsType[*apperrors.ConflictError](err); ok {
			return conflict
		}
		if published {
			err = fmt.Errorf("station-voice %d jingle published to %s but commit failed: %w", stationVoice.ID, outputPath, err)
			// Report the live file now and per station-voice: on a timeout the
			// handler logs neither this cause nor an alert, and its database
			// alert is per route and waits for a threshold.
			logger.Error("Jingle is live but its database record may be missing",
				"station_voice_id", stationVoice.ID, "path", outputPath, "error", err)
			s.alerts.Alert(ctx, notify.Event{
				Key:     alertKey,
				Summary: fmt.Sprintf("Station-voice %d jingle is live but its database record may be missing", stationVoice.ID),
				Details: err.Error() + "\n\nUpload this station-voice's jingle again to record it.",
			})
		}
		return apperrors.TranslateRepoErrorWithID("StationVoice", stationVoice.ID, apperrors.OpUpdate, err)
	}
	s.alerts.Resolve(ctx, alertKey,
		fmt.Sprintf("Station-voice %d jingle recorded again", stationVoice.ID),
		"A later publication saved the station-voice's jingle file.")

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
