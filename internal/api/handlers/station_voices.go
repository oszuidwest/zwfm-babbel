package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
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

// GetStationVoiceAudioURL returns the API URL for downloading a jingle file, or nil if no jingle.
func GetStationVoiceAudioURL(stationVoiceID int, hasJingle bool) *string {
	if !hasJingle {
		return nil
	}
	url := fmt.Sprintf("/api/v1/station_voices/%d/audio", stationVoiceID)
	return &url
}

// ListStationVoices returns a paginated list of station-voice relationships
func (h *Handlers) ListStationVoices(c *gin.Context) {
	// Build query configuration with JOINs to stations and voices
	config := utils.QueryConfig{
		BaseQuery: `SELECT sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point, 
		                 s.name as station_name, v.name as voice_name 
		          FROM station_voices sv 
		          JOIN stations s ON sv.station_id = s.id 
		          JOIN voices v ON sv.voice_id = v.id`,
		CountQuery:   "SELECT COUNT(*) FROM station_voices sv JOIN stations s ON sv.station_id = s.id JOIN voices v ON sv.voice_id = v.id",
		DefaultOrder: "sv.id DESC",
		Filters:      []utils.FilterConfig{},
		PostProcessor: func(result interface{}) {
			// Add audio URLs to response
			if stationVoices, ok := result.(*[]StationVoiceResponse); ok {
				for i := range *stationVoices {
					hasJingle := (*stationVoices)[i].JingleFile != ""
					(*stationVoices)[i].AudioURL = GetStationVoiceAudioURL((*stationVoices)[i].ID, hasJingle)
				}
			}
		},
	}

	// Add station_id filter if specified
	if stationID := c.Query("station_id"); stationID != "" {
		config.Filters = append(config.Filters, utils.FilterConfig{
			Column: "station_id",
			Table:  "sv",
			Value:  stationID,
		})
	}

	// Add voice_id filter if specified
	if voiceID := c.Query("voice_id"); voiceID != "" {
		config.Filters = append(config.Filters, utils.FilterConfig{
			Column: "voice_id",
			Table:  "sv",
			Value:  voiceID,
		})
	}

	var stationVoices []StationVoiceResponse
	utils.GenericListWithJoins(c, h.db, config, &stationVoices)
}

// GetStationVoice returns a single station-voice relationship by ID
func (h *Handlers) GetStationVoice(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
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
			utils.NotFound(c, "Station-voice relationship")
		} else {
			utils.InternalServerError(c, "Failed to fetch station-voice")
		}
		return
	}

	// Add audio URL
	hasJingle := stationVoice.JingleFile != ""
	stationVoice.AudioURL = GetStationVoiceAudioURL(stationVoice.ID, hasJingle)

	utils.Success(c, stationVoice)
}

// CreateStationVoice creates a new station-voice relationship with optional jingle upload
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	// Parse form data using the new utilities
	stationID, ok := utils.ParseRequiredIntForm(c, "station_id")
	if !ok {
		return
	}

	voiceID, ok := utils.ParseRequiredIntForm(c, "voice_id")
	if !ok {
		return
	}

	mixPointPtr, err := utils.ParseFloatFormWithRange(c, "mix_point", 0, 300)
	if err != nil {
		utils.BadRequest(c, err.Error())
		return
	}
	mixPoint := 0.0
	if mixPointPtr != nil {
		mixPoint = *mixPointPtr
	}

	// Check if station and voice exist
	if !utils.ValidateResourceExists(c, h.db, "stations", "Station", stationID) {
		return
	}
	if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", voiceID) {
		return
	}

	// Check if combination already exists
	count, err := utils.CountByCondition(h.db, "station_voices", "station_id = ? AND voice_id = ?", stationID, voiceID)
	if err != nil {
		utils.InternalServerError(c, "Failed to check uniqueness")
		return
	}
	if count > 0 {
		utils.BadRequest(c, "Station-voice combination already exists")
		return
	}

	// Create station-voice relationship
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO station_voices (station_id, voice_id, mix_point) VALUES (?, ?, ?)",
		stationID, voiceID, mixPoint)
	if err != nil {
		utils.InternalServerError(c, "Failed to create station-voice")
		return
	}

	id, _ := result.LastInsertId()

	// Handle optional jingle file upload
	_, _, err = c.Request.FormFile("jingle")
	if err == nil {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", stationID, voiceID))
		if err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
		defer cleanup()

		// Generate final path and move from temp
		finalPath := utils.GetJinglePath(h.config, stationID, voiceID)

		// Move from temp to final location (handles cross-device moves)
		if err := utils.SafeMoveFile(tempPath, finalPath); err != nil {
			logger.Error("Failed to move jingle file: %v", err)
			utils.InternalServerError(c, "Failed to save jingle file")
			return
		}

		// Update database with relative jingle path
		relativePath := utils.GetJingleRelativePath(h.config, stationID, voiceID)
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE station_voices SET jingle_file = ? WHERE id = ?", relativePath, id)
		if err != nil {
			// Clean up file on database error
			if err := os.Remove(finalPath); err != nil {
				logger.Error("Failed to remove temporary file: %v", err)
			}
			utils.InternalServerError(c, "Failed to update jingle reference")
			return
		}
	}

	utils.CreatedWithID(c, id, "Station-voice relationship created successfully")
}

// UpdateStationVoice updates an existing station-voice relationship
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if record exists
	if !utils.ValidateResourceExists(c, h.db, "station_voices", "Station-voice relationship", id) {
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	// Handle station_id update
	if stationIDStr := c.PostForm("station_id"); stationIDStr != "" {
		stationID, err := strconv.Atoi(stationIDStr)
		if err != nil || stationID <= 0 {
			utils.BadRequest(c, "Valid station_id is required")
			return
		}
		if !utils.ValidateResourceExists(c, h.db, "stations", "Station", stationID) {
			return
		}
		updates = append(updates, "station_id = ?")
		args = append(args, stationID)
	}

	// Handle voice_id update
	if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
		voiceID, err := strconv.Atoi(voiceIDStr)
		if err != nil || voiceID <= 0 {
			utils.BadRequest(c, "Valid voice_id is required")
			return
		}
		if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", voiceID) {
			return
		}
		updates = append(updates, "voice_id = ?")
		args = append(args, voiceID)
	}

	// Handle mix_point update
	if mixPointStr := c.PostForm("mix_point"); mixPointStr != "" {
		mixPoint, err := strconv.ParseFloat(mixPointStr, 64)
		if err != nil || mixPoint < 0 || mixPoint > 300 {
			utils.BadRequest(c, "Mix point must be between 0 and 300 seconds")
			return
		}
		updates = append(updates, "mix_point = ?")
		args = append(args, mixPoint)
	}

	if len(updates) == 0 {
		utils.BadRequest(c, "No fields to update")
		return
	}

	// Check uniqueness if station_id or voice_id is being updated
	if stationIDStr := c.PostForm("station_id"); stationIDStr != "" || c.PostForm("voice_id") != "" {
		// Get current record to determine final combination
		var current struct {
			StationID int `db:"station_id"`
			VoiceID   int `db:"voice_id"`
		}

		err := h.db.Get(&current, "SELECT station_id, voice_id FROM station_voices WHERE id = ?", id)
		if err != nil {
			utils.InternalServerError(c, "Failed to fetch current values")
			return
		}

		// Determine final values (use new if provided, current otherwise)
		finalStationID := current.StationID
		finalVoiceID := current.VoiceID

		if stationIDStr != "" {
			finalStationID, _ = strconv.Atoi(stationIDStr)
		}
		if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
			finalVoiceID, _ = strconv.Atoi(voiceIDStr)
		}

		// Check if this combination would create a duplicate (excluding current record)
		count, err := utils.CountByCondition(h.db, "station_voices",
			"station_id = ? AND voice_id = ? AND id != ?",
			finalStationID, finalVoiceID, id)

		if err != nil {
			utils.InternalServerError(c, "Failed to check uniqueness")
			return
		}

		if count > 0 {
			utils.BadRequest(c, "Station-voice combination already exists")
			return
		}
	}

	// Execute update
	query := "UPDATE station_voices SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	_, err := h.db.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		utils.InternalServerError(c, "Failed to update station-voice")
		return
	}

	// Get updated record for response
	var updatedRecord models.StationVoice
	err = h.db.Get(&updatedRecord, `
		SELECT sv.id, sv.station_id, sv.voice_id, sv.mix_point, sv.created_at, sv.updated_at,
			   s.name as station_name, v.name as voice_name
		FROM station_voices sv
		JOIN stations s ON sv.station_id = s.id  
		JOIN voices v ON sv.voice_id = v.id
		WHERE sv.id = ?`, id)
	if err != nil {
		utils.InternalServerError(c, "Failed to fetch updated record")
		return
	}

	utils.Success(c, updatedRecord)
}

// DeleteStationVoice deletes a station-voice relationship and associated jingle file
func (h *Handlers) DeleteStationVoice(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Get jingle file before deletion
	var jingleFile sql.NullString
	if err := h.db.Get(&jingleFile, "SELECT jingle_file FROM station_voices WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			utils.NotFound(c, "Station-voice relationship")
		} else {
			utils.InternalServerError(c, "Failed to fetch station-voice")
		}
		return
	}

	// Delete from database
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM station_voices WHERE id = ?", id)
	if err != nil {
		utils.InternalServerError(c, "Failed to delete station-voice")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.NotFound(c, "Station-voice relationship")
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
