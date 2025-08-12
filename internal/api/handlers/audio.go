// Package handlers provides HTTP request handlers for the Babbel API.
package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
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
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID parameter"})
		return
	}

	// Build query to get file path
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?",
		config.FileColumn, config.TableName, config.IDColumn)

	var filePath sql.NullString
	err = h.db.Get(&filePath, query, id)
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
