// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceResponse represents the response for station-voice relationships
type StationVoiceResponse struct {
	ID          int       `json:"id" db:"id"`
	StationID   int       `json:"station_id" db:"station_id"`
	VoiceID     int       `json:"voice_id" db:"voice_id"`
	JingleFile  string    `json:"-" db:"jingle_file"`
	MixPoint    float64   `json:"mix_point" db:"mix_point"`
	StationName string    `json:"station_name" db:"station_name"`
	VoiceName   string    `json:"voice_name" db:"voice_name"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	AudioURL    *string   `json:"audio_url,omitempty"`
}

// GetStationVoiceAudioURL returns the API URL for downloading a jingle file, or nil if no jingle.
func GetStationVoiceAudioURL(stationVoiceID int, hasJingle bool) *string {
	if !hasJingle {
		return nil
	}
	url := fmt.Sprintf("/station-voices/%d/audio", stationVoiceID)
	return &url
}

// ListStationVoices returns a paginated list of station-voice relationships with modern query parameter support.
// Supports advanced filtering, sorting, field selection, and full-text search.
// Search functionality covers station names and voice names for easy discovery.
func (h *Handlers) ListStationVoices(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point, 
			            sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name 
			            FROM station_voices sv 
			            JOIN stations s ON sv.station_id = s.id 
			            JOIN voices v ON sv.voice_id = v.id`,
			CountQuery:   "SELECT COUNT(*) FROM station_voices sv JOIN stations s ON sv.station_id = s.id JOIN voices v ON sv.voice_id = v.id",
			DefaultOrder: "sv.id DESC",
			PostProcessor: func(result interface{}) {
				// Add audio URLs to response
				if stationVoices, ok := result.(*[]StationVoiceResponse); ok {
					for i := range *stationVoices {
						hasJingle := (*stationVoices)[i].JingleFile != ""
						(*stationVoices)[i].AudioURL = GetStationVoiceAudioURL((*stationVoices)[i].ID, hasJingle)
					}
				}
			},
		},
		SearchFields:      []string{"s.name", "v.name"},
		TableAlias:        "sv",
		DefaultFields:     "sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point, sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name",
		DisableSoftDelete: true, // Station-voices table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":           "sv.id",
			"station_id":   "sv.station_id",
			"voice_id":     "sv.voice_id",
			"jingle_file":  "sv.jingle_file",
			"mix_point":    "sv.mix_point",
			"created_at":   "sv.created_at",
			"updated_at":   "sv.updated_at",
			"station_name": "s.name",
			"voice_name":   "v.name",
		},
	}

	var stationVoices []StationVoiceResponse
	utils.ModernListWithQuery(c, h.db, config, &stationVoices)
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
			utils.ProblemNotFound(c, "Station-voice relationship")
		} else {
			utils.ProblemInternalServer(c, "Failed to fetch station-voice")
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
	// Use unified validation that handles both JSON and form data
	var req utils.StationVoiceRequest
	if !utils.BindFormAndValidate(c, &req) {
		return
	}

	// Check if station and voice exist
	if !utils.ValidateResourceExists(c, h.db, "stations", "Station", req.StationID) {
		return
	}
	if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", req.VoiceID) {
		return
	}

	// Check if combination already exists
	count, err := utils.CountByCondition(h.db, "station_voices", "station_id = ? AND voice_id = ?", req.StationID, req.VoiceID)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check uniqueness")
		return
	}
	if count > 0 {
		utils.ProblemDuplicate(c, "Station-voice combination")
		return
	}

	// Create station-voice relationship
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO station_voices (station_id, voice_id, mix_point) VALUES (?, ?, ?)",
		req.StationID, req.VoiceID, req.MixPoint)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to create station-voice")
		return
	}

	id, _ := result.LastInsertId()

	// Handle optional jingle file upload
	_, _, err = c.Request.FormFile("jingle")
	if err == nil {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", req.StationID, req.VoiceID))
		if err != nil {
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "jingle",
				Message: err.Error(),
			}})
			return
		}
		defer cleanup()

		// Generate final path and move from temp
		finalPath := utils.GetJinglePath(h.config, req.StationID, req.VoiceID)

		// Move from temp to final location (handles cross-device moves)
		if err := utils.SafeMoveFile(tempPath, finalPath); err != nil {
			logger.Error("Failed to move jingle file: %v", err)
			utils.ProblemInternalServer(c, "Failed to save jingle file")
			return
		}

		// Update database with relative jingle path
		relativePath := utils.GetJingleRelativePath(h.config, req.StationID, req.VoiceID)
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE station_voices SET jingle_file = ? WHERE id = ?", relativePath, id)
		if err != nil {
			// Clean up file on database error
			if err := os.Remove(finalPath); err != nil {
				logger.Error("Failed to remove temporary file: %v", err)
			}
			utils.ProblemInternalServer(c, "Failed to update jingle reference")
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

	// Check if this is JSON input or form data
	contentType := c.GetHeader("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	if isJSON {
		// Handle JSON input for PUT requests
		var req struct {
			StationID *int     `json:"station_id,omitempty"`
			VoiceID   *int     `json:"voice_id,omitempty"`
			MixPoint  *float64 `json:"mix_point,omitempty"`
		}

		if !utils.BindAndValidate(c, &req) {
			return
		}

		// Process JSON fields
		if req.StationID != nil {
			if *req.StationID <= 0 {
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "station_id",
					Message: "Valid station_id is required",
				}})
				return
			}
			if !utils.ValidateResourceExists(c, h.db, "stations", "Station", *req.StationID) {
				return
			}
			updates = append(updates, "station_id = ?")
			args = append(args, *req.StationID)
		}

		if req.VoiceID != nil {
			if *req.VoiceID <= 0 {
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "voice_id",
					Message: "Valid voice_id is required",
				}})
				return
			}
			if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", *req.VoiceID) {
				return
			}
			updates = append(updates, "voice_id = ?")
			args = append(args, *req.VoiceID)
		}

		if req.MixPoint != nil {
			if *req.MixPoint < 0 || *req.MixPoint > 300 {
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "mix_point",
					Message: "Mix point must be between 0 and 300 seconds",
				}})
				return
			}
			updates = append(updates, "mix_point = ?")
			args = append(args, *req.MixPoint)
		}
	} else {
		// Handle form data (existing logic)
		// Handle station_id update
		if stationIDStr := c.PostForm("station_id"); stationIDStr != "" {
			stationID, err := strconv.Atoi(stationIDStr)
			if err != nil || stationID <= 0 {
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "station_id",
					Message: "Valid station_id is required",
				}})
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
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "voice_id",
					Message: "Valid voice_id is required",
				}})
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
				utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
					Field:   "mix_point",
					Message: "Mix point must be between 0 and 300 seconds",
				}})
				return
			}
			updates = append(updates, "mix_point = ?")
			args = append(args, mixPoint)
		}
	}

	if len(updates) == 0 {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
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
			utils.ProblemInternalServer(c, "Failed to fetch current values")
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
			utils.ProblemInternalServer(c, "Failed to check uniqueness")
			return
		}

		if count > 0 {
			utils.ProblemDuplicate(c, "Station-voice combination")
			return
		}
	}

	// Execute update
	query := "UPDATE station_voices SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	_, err := h.db.ExecContext(c.Request.Context(), query, args...)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to update station-voice")
		return
	}

	// Get updated record for response
	var updatedRecord StationVoiceResponse
	err = h.db.Get(&updatedRecord, `
		SELECT sv.id, sv.station_id, sv.voice_id, sv.jingle_file, sv.mix_point, 
		       sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name
		FROM station_voices sv
		JOIN stations s ON sv.station_id = s.id  
		JOIN voices v ON sv.voice_id = v.id
		WHERE sv.id = ?`, id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to fetch updated record")
		return
	}

	// Add audio URL
	hasJingle := updatedRecord.JingleFile != ""
	updatedRecord.AudioURL = GetStationVoiceAudioURL(updatedRecord.ID, hasJingle)

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
			utils.ProblemNotFound(c, "Station-voice relationship")
		} else {
			utils.ProblemInternalServer(c, "Failed to fetch station-voice")
		}
		return
	}

	// Delete from database
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM station_voices WHERE id = ?", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to delete station-voice")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.ProblemNotFound(c, "Station-voice relationship")
		return
	}

	// Clean up jingle file if it exists
	if jingleFile.Valid && jingleFile.String != "" {
		filepath := filepath.Join(h.config.Audio.ProcessedPath, jingleFile.String)
		if err := os.Remove(filepath); err != nil {
			logger.Error("Failed to remove jingle file: %v", err)
		}
	}

	utils.NoContent(c)
}
