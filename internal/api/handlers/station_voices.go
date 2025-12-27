// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceResponse represents the response for station-voice relationships
type StationVoiceResponse struct {
	ID          int64     `json:"id" db:"id"`
	StationID   int64     `json:"station_id" db:"station_id"`
	VoiceID     int64     `json:"voice_id" db:"voice_id"`
	AudioFile   string    `json:"-" db:"audio_file"`
	MixPoint    float64   `json:"mix_point" db:"mix_point"`
	StationName string    `json:"station_name" db:"station_name"`
	VoiceName   string    `json:"voice_name" db:"voice_name"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	AudioURL    *string   `json:"audio_url,omitempty"`
}

// StationVoiceAudioURL returns the API URL for downloading a jingle file, or nil if no jingle.
func StationVoiceAudioURL(stationVoiceID int64, hasJingle bool) *string {
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
			BaseQuery: `SELECT sv.id, sv.station_id, sv.voice_id, sv.audio_file, sv.mix_point, 
			            sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name 
			            FROM station_voices sv 
			            JOIN stations s ON sv.station_id = s.id 
			            JOIN voices v ON sv.voice_id = v.id`,
			CountQuery:   "SELECT COUNT(*) FROM station_voices sv JOIN stations s ON sv.station_id = s.id JOIN voices v ON sv.voice_id = v.id",
			DefaultOrder: "sv.id DESC",
			PostProcessor: func(result any) {
				// Add audio URLs to response
				if stationVoices, ok := result.(*[]StationVoiceResponse); ok {
					for i := range *stationVoices {
						hasJingle := (*stationVoices)[i].AudioFile != ""
						(*stationVoices)[i].AudioURL = StationVoiceAudioURL((*stationVoices)[i].ID, hasJingle)
					}
				}
			},
		},
		SearchFields:      []string{"s.name", "v.name"},
		TableAlias:        "sv",
		DefaultFields:     "sv.id, sv.station_id, sv.voice_id, sv.audio_file, sv.mix_point, sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name",
		DisableSoftDelete: true, // Station-voices table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":           "sv.id",
			"station_id":   "sv.station_id",
			"voice_id":     "sv.voice_id",
			"audio_file":   "sv.audio_file",
			"mix_point":    "sv.mix_point",
			"created_at":   "sv.created_at",
			"updated_at":   "sv.updated_at",
			"station_name": "s.name",
			"voice_name":   "v.name",
		},
	}

	var stationVoices []StationVoiceResponse
	utils.ModernListWithQuery(c, h.stationVoiceSvc.DB(), config, &stationVoices)
}

// GetStationVoice returns a single station-voice relationship by ID
func (h *Handlers) GetStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	stationVoice, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	// Convert to response format and add audio URL
	response := StationVoiceResponse{
		ID:          stationVoice.ID,
		StationID:   stationVoice.StationID,
		VoiceID:     stationVoice.VoiceID,
		AudioFile:   stationVoice.AudioFile,
		MixPoint:    stationVoice.MixPoint,
		StationName: stationVoice.StationName,
		VoiceName:   stationVoice.VoiceName,
		CreatedAt:   stationVoice.CreatedAt,
		UpdatedAt:   stationVoice.UpdatedAt,
		AudioURL:    StationVoiceAudioURL(stationVoice.ID, stationVoice.AudioFile != ""),
	}

	utils.Success(c, response)
}

// CreateStationVoice creates a new station-voice relationship with optional jingle upload
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	// Only accept multipart/form-data for consistency with other file upload endpoints
	var req utils.StationVoiceRequest
	if err := c.ShouldBind(&req); err != nil {
		utils.ProblemValidationError(c, "Invalid form data", []utils.ValidationError{{
			Field:   "request_body",
			Message: "Invalid form data format",
		}})
		return
	}

	// Create station-voice relationship via service
	serviceReq := &services.CreateStationVoiceRequest{
		StationID: req.StationID,
		VoiceID:   req.VoiceID,
		MixPoint:  req.MixPoint,
	}

	stationVoice, err := h.stationVoiceSvc.Create(c.Request.Context(), serviceReq)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

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
		defer func() {
			if err := cleanup(); err != nil {
				logger.Error("Failed to cleanup jingle file: %v", err)
			}
		}()

		// Process jingle via service
		if err := h.stationVoiceSvc.ProcessJingle(c.Request.Context(), stationVoice.ID, tempPath); err != nil {
			handleServiceError(c, err, "Jingle processing")
			return
		}
	}

	utils.CreatedWithID(c, stationVoice.ID, "Station-voice relationship created successfully")
}

// stationVoiceUpdateRequest represents the update request structure
type stationVoiceUpdateRequest struct {
	StationID *int64   `form:"station_id,omitempty"`
	VoiceID   *int64   `form:"voice_id,omitempty"`
	MixPoint  *float64 `form:"mix_point,omitempty"`
}

// hasFieldUpdates checks if the request contains any field updates
func (r *stationVoiceUpdateRequest) hasFieldUpdates() bool {
	return r.StationID != nil || r.VoiceID != nil || r.MixPoint != nil
}

// validateStationVoiceUpdateRequest binds and validates the update request
func validateStationVoiceUpdateRequest(c *gin.Context) (*stationVoiceUpdateRequest, bool, bool) {
	var req stationVoiceUpdateRequest
	if err := c.ShouldBind(&req); err != nil {
		utils.ProblemValidationError(c, "Invalid form data", []utils.ValidationError{{
			Field:   "request_body",
			Message: "Invalid form data format",
		}})
		return nil, false, false
	}

	// Check if there's a jingle file to process
	hasJingleUpdate := false
	_, _, err := c.Request.FormFile("jingle")
	if err == nil {
		hasJingleUpdate = true
	}

	// Validate that there's something to update
	if !req.hasFieldUpdates() && !hasJingleUpdate {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return nil, false, false
	}

	return &req, hasJingleUpdate, true
}

// updateStationVoiceFields updates the station-voice relationship fields via service
func (h *Handlers) updateStationVoiceFields(c *gin.Context, id int64, req *stationVoiceUpdateRequest) bool {
	serviceReq := &services.UpdateStationVoiceRequest{
		StationID: req.StationID,
		VoiceID:   req.VoiceID,
		MixPoint:  req.MixPoint,
	}

	if _, err := h.stationVoiceSvc.Update(c.Request.Context(), id, serviceReq); err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return false
	}
	return true
}

// processStationVoiceJingleUpdate handles jingle file upload and processing
func (h *Handlers) processStationVoiceJingleUpdate(c *gin.Context, id int64) bool {
	// Get current station/voice IDs for the temporary file naming
	current, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return false
	}

	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", current.StationID, current.VoiceID))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "jingle",
			Message: err.Error(),
		}})
		return false
	}
	defer func() {
		if err := cleanup(); err != nil {
			logger.Error("Failed to cleanup jingle file: %v", err)
		}
	}()

	// Process jingle via service
	if err := h.stationVoiceSvc.ProcessJingle(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Jingle processing")
		return false
	}
	return true
}

// buildStationVoiceResponse converts a model to response format with audio URL
func buildStationVoiceResponse(sv *models.StationVoice) StationVoiceResponse {
	return StationVoiceResponse{
		ID:          sv.ID,
		StationID:   sv.StationID,
		VoiceID:     sv.VoiceID,
		AudioFile:   sv.AudioFile,
		MixPoint:    sv.MixPoint,
		StationName: sv.StationName,
		VoiceName:   sv.VoiceName,
		CreatedAt:   sv.CreatedAt,
		UpdatedAt:   sv.UpdatedAt,
		AudioURL:    StationVoiceAudioURL(sv.ID, sv.AudioFile != ""),
	}
}

// UpdateStationVoice updates an existing station-voice relationship
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Bind and validate request
	req, hasJingleUpdate, valid := validateStationVoiceUpdateRequest(c)
	if !valid {
		return
	}

	// Update station-voice relationship fields if provided
	if req.hasFieldUpdates() {
		if !h.updateStationVoiceFields(c, id, req) {
			return
		}
	}

	// Handle jingle file replacement if provided
	if hasJingleUpdate {
		if !h.processStationVoiceJingleUpdate(c, id) {
			return
		}
	}

	// Get updated record for response
	updatedRecord, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	utils.Success(c, buildStationVoiceResponse(updatedRecord))
}

// DeleteStationVoice deletes a station-voice relationship and associated jingle file
func (h *Handlers) DeleteStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Delete via service (handles both database and file cleanup)
	if err := h.stationVoiceSvc.Delete(c.Request.Context(), id); err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	utils.NoContent(c)
}
