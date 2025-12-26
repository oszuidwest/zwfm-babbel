// Package handlers provides HTTP request handlers for the Babbel API.
package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AudioConfig defines configuration parameters for serving audio files from database records.
// It specifies the table, columns, and content type for different audio resource types.
type AudioConfig struct {
	TableName   string
	IDColumn    string
	FileColumn  string
	FilePrefix  string
	ContentType string
	Directory   string // Directory within audio root (e.g. "processed", "output")
}

// ServeAudio serves an audio file from the filesystem with proper HTTP headers and security.
// Looks up the file path in the database using the provided configuration, validates the file exists,
// and streams it to the client with appropriate Content-Type and Content-Disposition headers.
//
// Security features:
//   - Database lookup prevents path traversal attacks
//   - File existence validation
//   - Proper error handling for missing files
//   - Content-Type enforcement
//
// Returns 404 if record or file doesn't exist, 500 for database errors.
func (h *Handlers) ServeAudio(c *gin.Context, config AudioConfig) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Build query to get file path
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?",
		config.FileColumn, config.TableName, config.IDColumn)

	var filePath sql.NullString
	err := h.db.Get(&filePath, query, id)
	if err == sql.ErrNoRows {
		utils.ProblemNotFound(c, "Record")
		return
	}
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to fetch record")
		return
	}

	// Check if filename exists
	if !filePath.Valid || filePath.String == "" {
		utils.ProblemNotFound(c, "Audio file")
		return
	}

	// Construct full path using directory and filename
	audioPath := filepath.Join(h.config.Audio.AppRoot, "audio", config.Directory, filePath.String)

	if _, err := os.Stat(audioPath); os.IsNotExist(err) {
		utils.ProblemNotFound(c, "Audio file")
		return
	}
	c.Header("Content-Type", config.ContentType)
	c.Header("Content-Disposition",
		fmt.Sprintf("inline; filename=\"%s_%d.wav\"", config.FilePrefix, id))

	c.File(audioPath)
}
