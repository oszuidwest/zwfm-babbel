// Package handlers provides HTTP request handlers for the Babbel API.
package handlers

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
)

// AudioConfig defines configuration parameters for serving audio files.
type AudioConfig struct {
	TableName   string
	IDColumn    string
	FileColumn  string
	FilePrefix  string
	ContentType string
}

// ServeAudio serves an audio file with proper headers and error handling.
func (h *Handlers) ServeAudio(c *gin.Context, config AudioConfig) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid ID")
		return
	}

	// Build query to get file path
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?",
		config.FileColumn, config.TableName, config.IDColumn)

	var filePath sql.NullString
	err = h.db.Get(&filePath, query, id)
	if err == sql.ErrNoRows {
		responses.NotFound(c, "Record not found")
		return
	}
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch record")
		return
	}

	// Check if file path exists
	if !filePath.Valid || filePath.String == "" {
		responses.NotFound(c, "No audio file for this record")
		return
	}

	// Use the stored path directly (it already includes the full path)
	audioPath := filePath.String

	// Check if file exists
	if _, err := os.Stat(audioPath); os.IsNotExist(err) {
		responses.NotFound(c, "Audio file not found")
		return
	}

	// Set appropriate headers
	c.Header("Content-Type", config.ContentType)
	c.Header("Content-Disposition",
		fmt.Sprintf("inline; filename=\"%s_%d.wav\"", config.FilePrefix, id))

	c.File(audioPath)
}
