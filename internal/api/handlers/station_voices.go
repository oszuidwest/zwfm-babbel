package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStationVoices returns a paginated list of station-voice relationships.
func (h *Handlers) ListStationVoices(c *gin.Context) {
	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	result, err := h.stationVoiceSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationships")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetStationVoice returns a station-voice relationship with computed fields
// populated by model hooks.
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

	utils.Success(c, stationVoice)
}

// CreateStationVoice accepts JSON and links a station to a newsreader voice.
func (h *Handlers) CreateStationVoice(c *gin.Context) {
	var req utils.StationVoiceRequest

	if !utils.BindAndValidate(c, &req) {
		return
	}

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

// UpdateStationVoice applies a JSON partial update to a station-voice link.
func (h *Handlers) UpdateStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.StationVoiceUpdateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	if req.StationID == nil && req.VoiceID == nil && req.MixPoint == nil {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return
	}

	serviceReq := &services.UpdateStationVoiceRequest{
		StationID: req.StationID,
		VoiceID:   req.VoiceID,
		MixPoint:  req.MixPoint,
	}

	updated, err := h.stationVoiceSvc.Update(c.Request.Context(), id, serviceReq)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	utils.Success(c, updated)
}

// DeleteStationVoice deletes a station-voice relationship and associated
// jingle file.
func (h *Handlers) DeleteStationVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if err := h.stationVoiceSvc.Delete(c.Request.Context(), id); err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	utils.NoContent(c)
}
