package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceResponse represents the response for station-voice relationships
type StationVoiceResponse struct {
	ID          int     `json:"id" db:"id"`
	StationID   int     `json:"station_id" db:"station_id"`
	VoiceID     int     `json:"voice_id" db:"voice_id"`
	JingleFile  string  `json:"-" db:"jingle_file"`
	MixPoint    float64 `json:"mix_point" db:"mix_point"`
	StationName string  `json:"station_name" db:"station_name"`
	VoiceName   string  `json:"voice_name" db:"voice_name"`
	AudioURL    *string `json:"audio_url,omitempty"`
}

// GetStationVoiceAudioURL returns the API URL for a station-voice jingle file
func GetStationVoiceAudioURL(stationVoiceID int, hasJingle bool) *string {
	if !hasJingle {
		return nil
	}
	url := fmt.Sprintf("/api/v1/station_voices/%d/audio", stationVoiceID)
	return &url
}

// ListStationVoices returns a paginated list of station-voice relationships
func (h *Handlers) ListStationVoices(c *gin.Context) {
	limit, offset := api.GetPagination(c)

	// Build query with optional filters
	query := `SELECT sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point, 
	                 s.name as station_name, v.name as voice_name 
	          FROM station_voices sv 
	          JOIN stations s ON sv.station_id = s.id 
	          JOIN voices v ON sv.voice_id = v.id`
	
	countQuery := "SELECT COUNT(*) FROM station_voices sv JOIN stations s ON sv.station_id = s.id JOIN voices v ON sv.voice_id = v.id"
	args := []interface{}{}
	whereClauses := []string{}

	// Add filters if provided
	if stationID := c.Query("station_id"); stationID != "" {
		whereClauses = append(whereClauses, "sv.station_id = ?")
		args = append(args, stationID)
	}
	if voiceID := c.Query("voice_id"); voiceID != "" {
		whereClauses = append(whereClauses, "sv.voice_id = ?")
		args = append(args, voiceID)
	}

	// Apply WHERE clauses
	if len(whereClauses) > 0 {
		whereClause := " WHERE " + strings.Join(whereClauses, " AND ")
		query += whereClause
		countQuery += whereClause
	}

	// Get total count
	var total int64
	if err := h.db.Get(&total, countQuery, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count station-voices"})
		return
	}

	// Get paginated data
	query += " ORDER BY sv.id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	var stationVoices []StationVoiceResponse
	if err := h.db.Select(&stationVoices, query, args...); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch station-voices"})
		return
	}

	// Add audio URLs
	for i := range stationVoices {
		hasJingle := stationVoices[i].JingleFile != ""
		stationVoices[i].AudioURL = GetStationVoiceAudioURL(stationVoices[i].ID, hasJingle)
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   stationVoices,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetStationVoice returns a single station-voice relationship by ID
func (h *Handlers) GetStationVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var stationVoice StationVoiceResponse
	query := `SELECT sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point,
	                 s.name as station_name, v.name as voice_name
	          FROM station_voices sv
	          JOIN stations s ON sv.station_id = s.id
	          JOIN voices v ON sv.voice_id = v.id
	          WHERE sv.id = ?`

	if err := h.db.Get(&stationVoice, query, id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Station-voice relationship not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch station-voice"})
		}
		return
	}

	// Add audio URL
	hasJingle := stationVoice.JingleFile != ""
	stationVoice.AudioURL = GetStationVoiceAudioURL(stationVoice.ID, hasJingle)

	c.JSON(http.StatusOK, stationVoice)
}

// CreateStationVoice creates a new station-voice relationship with optional jingle upload
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	// Parse form data
	stationIDStr := c.PostForm("station_id")
	voiceIDStr := c.PostForm("voice_id")
	mixPointStr := c.PostForm("mix_point")

	stationID, err := strconv.Atoi(stationIDStr)
	if err != nil || stationID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid station_id is required"})
		return
	}

	voiceID, err := strconv.Atoi(voiceIDStr)
	if err != nil || voiceID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Valid voice_id is required"})
		return
	}

	mixPoint := 0.0
	if mixPointStr != "" {
		mixPoint, err = strconv.ParseFloat(mixPointStr, 64)
		if err != nil || mixPoint < 0 || mixPoint > 300 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mix_point must be between 0 and 300"})
			return
		}
	}

	// Check if station and voice exist
	if !api.ValidateResourceExists(c, h.db, "stations", "Station", stationID) {
		return
	}
	if !api.ValidateResourceExists(c, h.db, "voices", "Voice", voiceID) {
		return
	}

	// Check if combination already exists
	var count int
	if err := h.db.Get(&count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ? AND voice_id = ?", stationID, voiceID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check uniqueness"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Station-voice combination already exists"})
		return
	}

	// Create station-voice relationship
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO station_voices (station_id, voice_id, mix_point) VALUES (?, ?, ?)",
		stationID, voiceID, mixPoint)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create station-voice"})
		return
	}

	id, _ := result.LastInsertId()

	// Handle optional jingle file upload
	_, _, err = c.Request.FormFile("jingle")
	if err == nil {
		tempPath, cleanup, err := api.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", stationID, voiceID))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		defer cleanup()

		// Generate final filename and move from temp
		filename := fmt.Sprintf("station_%d_voice_%d_jingle.wav", stationID, voiceID)
		finalPath := filepath.Join(h.config.Audio.ProcessedPath, filename)

		// Move from temp to final location
		if err := os.Rename(tempPath, finalPath); err != nil {
			logger.Error("Failed to move jingle file: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save jingle file"})
			return
		}

		// Update database with jingle filename
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE station_voices SET jingle_file = ? WHERE id = ?", filename, id)
		if err != nil {
			// Clean up file on database error
			os.Remove(finalPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update jingle reference"})
			return
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": "Station-voice relationship created successfully",
	})
}

// UpdateStationVoice updates an existing station-voice relationship
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Check if record exists
	if !api.ValidateResourceExists(c, h.db, "station_voices", "Station-voice relationship", id) {
		return
	}

	// Parse form data
	var req api.StationVoiceRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check if referenced records exist
	if !api.ValidateResourceExists(c, h.db, "stations", "Station", req.StationID) {
		return
	}
	if !api.ValidateResourceExists(c, h.db, "voices", "Voice", req.VoiceID) {
		return
	}

	// Check uniqueness (excluding current record)
	var count int
	if err := h.db.Get(&count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ? AND voice_id = ? AND id != ?", req.StationID, req.VoiceID, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check uniqueness"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Station-voice combination already exists"})
		return
	}

	// Update station-voice
	_, err := h.db.ExecContext(c.Request.Context(),
		"UPDATE station_voices SET station_id = ?, voice_id = ?, mix_point = ? WHERE id = ?",
		req.StationID, req.VoiceID, req.MixPoint, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update station-voice"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Station-voice relationship updated successfully"})
}

// DeleteStationVoice deletes a station-voice relationship and associated jingle file
func (h *Handlers) DeleteStationVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Get jingle file before deletion
	var jingleFile sql.NullString
	if err := h.db.Get(&jingleFile, "SELECT jingle_file FROM station_voices WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Station-voice relationship not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch station-voice"})
		}
		return
	}

	// Delete from database
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM station_voices WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete station-voice"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Station-voice relationship not found"})
		return
	}

	// Clean up jingle file if it exists
	if jingleFile.Valid && jingleFile.String != "" {
		filepath := filepath.Join(h.config.Audio.ProcessedPath, jingleFile.String)
		if err := os.Remove(filepath); err != nil {
			logger.Error("Failed to remove jingle file: %v", err)
		}
	}

	c.Status(http.StatusNoContent)
}

