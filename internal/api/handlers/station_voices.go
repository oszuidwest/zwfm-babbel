package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

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

	// Return directly - AfterFind hook populates computed fields
	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// GetStationVoice returns a single station-voice relationship by ID.
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

	// Return directly - AfterFind hook populates computed fields
	utils.Success(c, stationVoice)
}

// CreateStationVoice creates a new station-voice relationship (JSON API only).
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

	utils.CreatedWithLocation(c, stationVoice.ID, "/api/v1/station-voices", "Station-voice relationship created successfully")
}

// hasStationVoiceFieldUpdates reports whether the request contains any field updates.
func hasStationVoiceFieldUpdates(req *utils.StationVoiceUpdateRequest) bool {
	return req.StationID != nil || req.VoiceID != nil || req.MixPoint != nil
}

// updateStationVoiceFields updates the station-voice relationship fields via service.
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

// UpdateStationVoice updates an existing station-voice relationship.
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

	// Get updated record for response - AfterFind hook populates computed fields
	updatedRecord, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	utils.Success(c, updatedRecord)
}

// DeleteStationVoice deletes a station-voice relationship and associated jingle file.
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
