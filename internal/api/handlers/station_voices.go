package handlers

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/api/validation"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// GetStationVoiceAudioURL returns the API URL for a station-voice jingle file
func GetStationVoiceAudioURL(stationVoiceID int, hasJingle bool) *string {
	if !hasJingle {
		return nil
	}
	url := fmt.Sprintf("/api/v1/station_voices/%d/audio", stationVoiceID)
	return &url
}

// StationVoiceInput represents the input for creating or updating a station-voice relationship.
type StationVoiceInput struct {
	StationID int     `json:"station_id" binding:"required"`
	VoiceID   int     `json:"voice_id" binding:"required"`
	MixPoint  float64 `json:"mix_point" binding:"min=0"`
}

// ListStationVoices lists all station-voice relationships
// ListStationVoices returns a paginated list of station-voice relationships.
func (h *Handlers) ListStationVoices(c *gin.Context) {
	crud := NewCRUDHandler(
		h.db,
		"station_voices sv",
		WithOrderBy("sv.id DESC"),
		WithSelectColumns("sv.*, s.name as station_name, v.name as voice_name"),
		WithJoins("JOIN stations s ON sv.station_id = s.id JOIN voices v ON sv.voice_id = v.id"),
	)

	var stationVoices []models.StationVoice
	filters := map[string]string{
		"sv.station_id": "station_id",
		"sv.voice_id":   "voice_id",
	}

	total, err := crud.List(c, &stationVoices, filters)
	if err != nil {
		responses.InternalServerError(c, err.Error())
		return
	}

	// Convert to response format with jingle URLs
	svResponses := make([]interface{}, len(stationVoices))
	for i, sv := range stationVoices {
		sv.JingleURL = GetStationVoiceAudioURL(sv.ID, sv.JingleFile != "")
		svResponses[i] = sv
	}

	limit, offset := extractPaginationParams(c)
	responses.Paginated(c, svResponses, total, limit, offset)
}

// GetStationVoice gets a specific station-voice relationship
// GetStationVoice returns a single station-voice relationship by ID.
func (h *Handlers) GetStationVoice(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid station voice ID")
		return
	}

	var stationVoice models.StationVoice
	err = h.db.Get(&stationVoice, `
		SELECT sv.*, s.name as station_name, v.name as voice_name 
		FROM station_voices sv 
		JOIN stations s ON sv.station_id = s.id 
		JOIN voices v ON sv.voice_id = v.id 
		WHERE sv.id = ?`, id)
	if err == sql.ErrNoRows {
		responses.NotFound(c, "Station voice not found")
		return
	}
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch station voice")
		return
	}

	// Add jingle URL if exists
	if stationVoice.JingleFile != "" {
		stationVoice.JingleURL = GetStationVoiceAudioURL(stationVoice.ID, true)
	}

	responses.Success(c, stationVoice)
}

// CreateStationVoice creates a new station-voice relationship
// CreateStationVoice creates a new station-voice relationship with jingle upload.
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	// Parse form data
	stationID := getIntForm(c, "station_id", 0)
	voiceID := getIntForm(c, "voice_id", 0)
	mixPoint := getFloatForm(c, "mix_point", 0.0)

	if stationID == 0 || voiceID == 0 {
		responses.BadRequest(c, "station_id and voice_id are required")
		return
	}

	// Check if station exists
	if !h.stationExists(stationID) {
		responses.BadRequest(c, "Station not found")
		return
	}

	// Check if voice exists
	var voiceExists bool
	if err := h.db.Get(&voiceExists, "SELECT EXISTS(SELECT 1 FROM voices WHERE id = ?)", voiceID); err != nil || !voiceExists {
		responses.BadRequest(c, "Voice not found")
		return
	}

	// Check if combination already exists
	var exists bool
	if err := h.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM station_voices WHERE station_id = ? AND voice_id = ?)", stationID, voiceID); err == nil && exists {
		responses.BadRequest(c, "Station voice combination already exists")
		return
	}

	// Handle jingle file upload
	jingleFile := ""
	if file, err := c.FormFile("jingle"); err == nil {
		// Validate audio file
		if err := validation.ValidateAudioFile(file); err != nil {
			responses.BadRequest(c, fmt.Sprintf("Invalid jingle file: %v", err))
			return
		}

		// Sanitize filename
		safeFilename := validation.SanitizeFilename(file.Filename)

		// Save to /tmp for processing
		tempPath := fmt.Sprintf("/tmp/upload_%d_%d_%s", stationID, voiceID, safeFilename)

		if err := c.SaveUploadedFile(file, tempPath); err != nil {
			responses.InternalServerError(c, fmt.Sprintf("Failed to save jingle file: %v", err))
			return
		}

		// Clean up temp file after processing
		defer func() {
			_ = os.Remove(tempPath)
		}()

		// Process jingle with audio service using station-specific processing
		processedPath, err := h.audioSvc.ConvertJingleToWAV(c.Request.Context(), stationID, voiceID, tempPath)
		if err != nil {
			responses.InternalServerError(c, fmt.Sprintf("Failed to process jingle: %v", err))
			return
		}

		jingleFile = processedPath
	}

	// Create station voice
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO station_voices (station_id, voice_id, jingle_file, mix_point) VALUES (?, ?, ?, ?)",
		stationID, voiceID, jingleFile, mixPoint,
	)
	if err != nil {
		responses.InternalServerError(c, "Failed to create station voice")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		responses.InternalServerError(c, "Failed to get station voice ID")
		return
	}

	// Fetch the created station voice
	var stationVoice models.StationVoice
	if err := h.db.Get(&stationVoice,
		`SELECT sv.*, s.name as station_name, v.name as voice_name 
		 FROM station_voices sv 
		 JOIN stations s ON sv.station_id = s.id 
		 JOIN voices v ON sv.voice_id = v.id 
		 WHERE sv.id = ?`, id); err != nil {
		responses.InternalServerError(c, "Failed to fetch created station voice")
		return
	}

	// Add jingle URL if exists
	if stationVoice.JingleFile != "" {
		stationVoice.JingleURL = GetStationVoiceAudioURL(stationVoice.ID, true)
	}

	responses.Created(c, stationVoice)
}

// UpdateStationVoice updates a station-voice relationship
// UpdateStationVoice updates an existing station-voice relationship.
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid station voice ID")
		return
	}

	// Handle multipart form data for jingle upload
	mixPoint := getFloatForm(c, "mix_point", 0.0)

	// Check if station voice exists
	var exists bool
	if err := h.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM station_voices WHERE id = ?)", id); err != nil || !exists {
		responses.NotFound(c, "Station voice not found")
		return
	}

	// Handle jingle file upload
	jingleFile := ""
	if file, err := c.FormFile("jingle"); err == nil {
		// Validate audio file
		if err := validation.ValidateAudioFile(file); err != nil {
			responses.BadRequest(c, fmt.Sprintf("Invalid jingle file: %v", err))
			return
		}

		// Get station and voice IDs from existing record
		var sv models.StationVoice
		if err := h.db.Get(&sv, "SELECT station_id, voice_id FROM station_voices WHERE id = ?", id); err != nil {
			responses.InternalServerError(c, "Failed to fetch station voice")
			return
		}

		// Sanitize filename
		safeFilename := validation.SanitizeFilename(file.Filename)

		// Save to /tmp for processing
		tempPath := fmt.Sprintf("/tmp/upload_%d_%d_%s", sv.StationID, sv.VoiceID, safeFilename)

		if err := c.SaveUploadedFile(file, tempPath); err != nil {
			responses.InternalServerError(c, "Failed to save jingle file")
			return
		}

		// Clean up temp file after processing
		defer func() {
			_ = os.Remove(tempPath)
		}()

		// Process jingle with audio service using station-specific processing
		processedPath, err := h.audioSvc.ConvertJingleToWAV(c.Request.Context(), sv.StationID, sv.VoiceID, tempPath)
		if err != nil {
			responses.InternalServerError(c, "Failed to process jingle")
			return
		}

		jingleFile = processedPath
	}

	// Build update query dynamically
	qb := NewQueryBuilder()
	qb.AddUpdateFloat("mix_point", mixPoint, true)
	if jingleFile != "" {
		qb.AddUpdate("jingle_file", jingleFile)
	}

	// Update station voice
	if qb.HasUpdates() {
		query, args := qb.BuildUpdateQuery("station_voices", id)
		_, err = h.db.ExecContext(c.Request.Context(), query, args...)
	} else {
		// No updates to perform
		err = nil
	}

	if err != nil {
		responses.InternalServerError(c, "Failed to update station voice")
		return
	}

	// Fetch updated station voice
	var stationVoice models.StationVoice
	if err := h.db.Get(&stationVoice,
		`SELECT sv.*, s.name as station_name, v.name as voice_name 
		 FROM station_voices sv 
		 JOIN stations s ON sv.station_id = s.id 
		 JOIN voices v ON sv.voice_id = v.id 
		 WHERE sv.id = ?`, id); err != nil {
		responses.InternalServerError(c, "Failed to fetch updated station voice")
		return
	}

	// Add jingle URL if exists
	if stationVoice.JingleFile != "" {
		stationVoice.JingleURL = GetStationVoiceAudioURL(stationVoice.ID, true)
	}

	responses.Success(c, stationVoice)
}

// DeleteStationVoice deletes a station-voice relationship
// DeleteStationVoice deletes a station-voice relationship and its jingle file.
func (h *Handlers) DeleteStationVoice(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid station voice ID")
		return
	}

	// Get station voice details including jingle file path
	var sv models.StationVoice
	err = h.db.Get(&sv, "SELECT * FROM station_voices WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			responses.NotFound(c, "Station voice not found")
		} else {
			responses.InternalServerError(c, "Failed to fetch station voice")
		}
		return
	}

	// Delete from database
	if _, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM station_voices WHERE id = ?", id); err != nil {
		responses.InternalServerError(c, "Failed to delete station voice")
		return
	}

	// Delete jingle file if it exists
	if sv.JingleFile != "" {
		jinglePath := filepath.Join(h.config.Audio.ProcessedPath, sv.JingleFile)
		if err := os.Remove(jinglePath); err != nil && !os.IsNotExist(err) {
			// Log error but don't fail the request
			// The database record is already deleted
			fmt.Printf("Warning: Failed to delete jingle file %s: %v\n", jinglePath, err)
		}
	}

	responses.NoContent(c)
}

// GetStationVoiceAudio serves the jingle audio file for a station-voice combination
// GetStationVoiceAudio serves the jingle audio file for a station-voice.
func (h *Handlers) GetStationVoiceAudio(c *gin.Context) {
	h.ServeAudio(c, AudioConfig{
		TableName:   "station_voices",
		IDColumn:    "id",
		FileColumn:  "jingle_file",
		FilePrefix:  "jingle",
		ContentType: "audio/wav",
	})
}
