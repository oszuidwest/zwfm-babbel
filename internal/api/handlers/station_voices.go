// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
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

// ListStationVoices returns a paginated list of station-voice relationships.
func (h *Handlers) ListStationVoices(c *gin.Context) {
	// Parse query parameters
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Convert to repository ListQuery
	query := convertToListQuery(params)

	// Call service
	result, err := h.stationVoiceSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationships")
		return
	}

	// Convert to response format with audio URLs
	responses := make([]StationVoiceResponse, len(result.Data))
	for i, sv := range result.Data {
		responses[i] = buildStationVoiceResponse(&sv)
	}

	utils.PaginatedResponse(c, responses, result.Total, result.Limit, result.Offset)
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

	// Get names from preloaded relations
	stationName := ""
	if stationVoice.Station != nil {
		stationName = stationVoice.Station.Name
	}
	voiceName := ""
	if stationVoice.Voice != nil {
		voiceName = stationVoice.Voice.Name
	}

	// Convert to response format and add audio URL
	response := StationVoiceResponse{
		ID:          stationVoice.ID,
		StationID:   stationVoice.StationID,
		VoiceID:     stationVoice.VoiceID,
		AudioFile:   stationVoice.AudioFile,
		MixPoint:    stationVoice.MixPoint,
		StationName: stationName,
		VoiceName:   voiceName,
		CreatedAt:   stationVoice.CreatedAt,
		UpdatedAt:   stationVoice.UpdatedAt,
		AudioURL:    StationVoiceAudioURL(stationVoice.ID, stationVoice.AudioFile != ""),
	}

	utils.Success(c, response)
}

// CreateStationVoice creates a new station-voice relationship (JSON API only)
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	var req utils.StationVoiceRequest

	// Pure JSON binding - no form-data support
	if !utils.BindAndValidate(c, &req) {
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

	utils.CreatedWithID(c, stationVoice.ID, "Station-voice relationship created successfully")
}

// hasStationVoiceFieldUpdates reports whether the request contains any field updates.
func hasStationVoiceFieldUpdates(req *utils.StationVoiceUpdateRequest) bool {
	return req.StationID != nil || req.VoiceID != nil || req.MixPoint != nil
}

// updateStationVoiceFields updates the station-voice relationship fields via service
func (h *Handlers) updateStationVoiceFields(c *gin.Context, id int64, req *utils.StationVoiceUpdateRequest) bool {
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

// buildStationVoiceResponse converts a model to response format with audio URL
func buildStationVoiceResponse(sv *models.StationVoice) StationVoiceResponse {
	// Get names from preloaded relations
	stationName := ""
	if sv.Station != nil {
		stationName = sv.Station.Name
	}
	voiceName := ""
	if sv.Voice != nil {
		voiceName = sv.Voice.Name
	}

	return StationVoiceResponse{
		ID:          sv.ID,
		StationID:   sv.StationID,
		VoiceID:     sv.VoiceID,
		AudioFile:   sv.AudioFile,
		MixPoint:    sv.MixPoint,
		StationName: stationName,
		VoiceName:   voiceName,
		CreatedAt:   sv.CreatedAt,
		UpdatedAt:   sv.UpdatedAt,
		AudioURL:    StationVoiceAudioURL(sv.ID, sv.AudioFile != ""),
	}
}

// UpdateStationVoice updates an existing station-voice relationship (JSON API only)
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Pure JSON binding - no form-data support
	var req utils.StationVoiceUpdateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Validate that there's at least one field to update
	if !hasStationVoiceFieldUpdates(&req) {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return
	}

	// Update station-voice relationship fields
	if !h.updateStationVoiceFields(c, id, &req) {
		return
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
