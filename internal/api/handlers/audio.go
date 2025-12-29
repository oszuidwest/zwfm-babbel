// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AudioConfig defines configuration parameters for serving audio files.
type AudioConfig struct {
	TableName   string
	IDColumn    string
	FileColumn  string
	FilePrefix  string
	ContentType string
	Directory   string // Directory within audio root (e.g. "processed", "output")
}

// ServeAudio serves an audio file with proper HTTP headers.
func (h *Handlers) ServeAudio(c *gin.Context, config AudioConfig) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Get file path from repository
	filePath, err := h.audioRepo.GetFilePath(c.Request.Context(), config.TableName, config.FileColumn, config.IDColumn, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			utils.ProblemNotFound(c, "Audio file")
			return
		}
		utils.ProblemInternalServer(c, "Failed to fetch record")
		return
	}

	// Construct full path using directory and filename
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

// UploadStoryAudio handles audio file upload for a story
func (h *Handlers) UploadStoryAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Validate that story exists
	_, err := h.storySvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	// Get and validate audio file
	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", id))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "audio",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "audio file")()

	// Process audio via service
	if err := h.storySvc.ProcessAudio(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithMessage(c, "Audio uploaded successfully")
}

// UploadStationVoiceAudio handles jingle file upload for a station-voice relationship
func (h *Handlers) UploadStationVoiceAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Get current station-voice to validate existence and get IDs for temp file naming
	stationVoice, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	// Get and validate jingle file
	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", stationVoice.StationID, stationVoice.VoiceID))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "jingle",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "jingle file")()

	// Process jingle via service
	if err := h.stationVoiceSvc.ProcessJingle(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Jingle processing")
		return
	}

	utils.CreatedWithMessage(c, "Jingle uploaded successfully")
}
