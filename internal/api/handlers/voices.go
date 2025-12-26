// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListVoices returns a paginated list of newsreader voices with search and sorting support.
// Supports modern query parameters: search, filtering, sorting, field selection, and pagination.
// Requires 'voices' read permission. Returns voice data with metadata including total count and pagination info.
func (h *Handlers) ListVoices(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery:    "SELECT v.* FROM voices v",
			CountQuery:   "SELECT COUNT(*) FROM voices v",
			DefaultOrder: "v.name ASC",
		},
		SearchFields:      []string{"v.name"},
		TableAlias:        "v",
		DefaultFields:     "v.*",
		DisableSoftDelete: true, // Voices table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":         "v.id",
			"name":       "v.name",
			"created_at": "v.created_at",
			"updated_at": "v.updated_at",
		},
	}

	var voices []models.Voice
	utils.ModernListWithQuery(c, h.db, config, &voices)
}

// GetVoice returns a single newsreader voice by ID with all configuration details.
// Requires 'voices' read permission. Returns 404 if voice doesn't exist.
func (h *Handlers) GetVoice(c *gin.Context) {
	var voice models.Voice
	utils.GenericGetByID(c, h.db, "voices", "Voice", &voice)
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

	utils.CreatedWithID(c, int64(voice.ID), "Voice created successfully")
}

// UpdateVoice updates an existing newsreader voice's name and configuration.
// Validates voice existence and name uniqueness (excluding current voice).
// Requires 'voices' write permission. Returns 404 if voice doesn't exist, 409 for name conflicts.
func (h *Handlers) UpdateVoice(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var req utils.VoiceRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	err := h.voiceSvc.Update(c.Request.Context(), id, req.Name)
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
	id, ok := utils.GetIDParam(c)
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
