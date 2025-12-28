// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListVoices returns a paginated list of newsreader voices with search and sorting support.
// Supports modern query parameters: search, filtering, sorting, field selection, and pagination.
// Requires 'voices' read permission. Returns voice data with metadata including total count and pagination info.
func (h *Handlers) ListVoices(c *gin.Context) {
	query := utils.ParseListQuery(c)

	result, err := h.voiceSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// GetVoice returns a single newsreader voice by ID with all configuration details.
// Requires 'voices' read permission. Returns 404 if voice doesn't exist.
func (h *Handlers) GetVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	voice, err := h.voiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	c.JSON(http.StatusOK, voice)
}

// CreateVoice creates a new newsreader voice for text-to-speech and jingle association.
// Validates that voice names are unique across the system. Requires 'voices' write permission.
// Returns 201 Created with the new voice ID on success, 409 Conflict for duplicate names.
func (h *Handlers) CreateVoice(c *gin.Context) {
	var req utils.VoiceRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	voice, err := h.voiceSvc.Create(c.Request.Context(), req.Name)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.CreatedWithID(c, voice.ID, "Voice created successfully")
}

// UpdateVoice updates an existing newsreader voice's name and configuration.
// Validates voice existence and name uniqueness (excluding current voice).
// Requires 'voices' write permission. Returns 404 if voice doesn't exist, 409 for name conflicts.
func (h *Handlers) UpdateVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.VoiceRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Convert to service update request
	updateReq := &services.UpdateVoiceRequest{
		Name: &req.Name,
	}

	err := h.voiceSvc.Update(c.Request.Context(), id, updateReq)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.SuccessWithMessage(c, "Voice updated successfully")
}

// DeleteVoice removes a newsreader voice after validating no dependencies exist.
// Checks for associated stories and station-voices before deletion to maintain referential integrity.
// Requires 'voices' write permission. Returns 409 Conflict if dependencies exist, 404 if not found.
func (h *Handlers) DeleteVoice(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	err := h.voiceSvc.Delete(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.NoContent(c)
}
