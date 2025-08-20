// Package handlers provides HTTP request handlers for the Babbel API.
package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AudioConfig defines configuration parameters for serving audio files from database records.
// Used to configure which table, columns, and content type to use for audio serving.
// Enables reusable audio serving logic across different resource types (stories, jingles, bulletins).
type AudioConfig struct {
	TableName   string
	IDColumn    string
	FileColumn  string
	FilePrefix  string
	ContentType string
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
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch record"})
		return
	}

	// Check if file path exists
	if !filePath.Valid || filePath.String == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No audio file for this record"})
		return
	}

	audioPath := filepath.Join(h.config.Audio.AppRoot, filePath.String)

	if _, err := os.Stat(audioPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audio file not found"})
		return
	}
	c.Header("Content-Type", config.ContentType)
	c.Header("Content-Disposition",
		fmt.Sprintf("inline; filename=\"%s_%d.wav\"", config.FilePrefix, id))

	c.File(audioPath)
}
