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
