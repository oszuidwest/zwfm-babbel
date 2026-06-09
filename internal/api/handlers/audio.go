package handlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AudioConfig maps an audio endpoint to the database column and storage
// directory that contain its WAV filename.
type AudioConfig struct {
	TableName   string
	IDColumn    string
	FileColumn  string
	FilePrefix  string
	ContentType string
	Directory   string // Directory within audio root (e.g. "processed", "output")
}

// ServeAudio streams a stored WAV file for the route ID.
// Missing database records and missing files are both reported as 404 so
// callers do not need to distinguish metadata from storage state.
func (h *Handlers) ServeAudio(c *gin.Context, config AudioConfig) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	filePath, err := h.audioRepo.GetFilePath(c.Request.Context(), config.TableName, config.FileColumn, config.IDColumn, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			utils.ProblemNotFound(c, "Audio file")
			return
		}
		utils.ProblemInternalServer(c, "Failed to fetch record")
		return
	}

	audioPath := filepath.Join(h.config.Audio.AppRoot, "audio", config.Directory, filePath)

	if _, err := os.Stat(audioPath); err != nil {
		if os.IsNotExist(err) {
			utils.ProblemNotFound(c, "Audio file")
		} else {
			utils.ProblemInternalServer(c, "Failed to access audio file")
		}
		return
	}
	c.Header("Content-Type", config.ContentType)
	c.Header("Content-Disposition",
		fmt.Sprintf("inline; filename=\"%s_%d.wav\"", config.FilePrefix, id))

	c.File(audioPath)
}

// UploadStoryAudio validates and converts an uploaded story file.
// The story must exist before temporary upload data is accepted.
func (h *Handlers) UploadStoryAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	_, err := h.storySvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", id))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "audio",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "audio file")()

	if err := h.storySvc.ProcessAudio(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithMessage(c, "Audio uploaded successfully")
}

// UploadStationVoiceAudio validates and converts a station-voice jingle.
// The current relationship supplies the station and voice IDs used for the
// canonical output filename.
func (h *Handlers) UploadStationVoiceAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	stationVoice, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", stationVoice.StationID, stationVoice.VoiceID))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "jingle",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "jingle file")()

	if err := h.stationVoiceSvc.ProcessJingle(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Jingle processing")
		return
	}

	utils.CreatedWithMessage(c, "Jingle uploaded successfully")
}
