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

	// Check name uniqueness
	if err := utils.CheckUnique(h.db, "voices", "name", req.Name, nil); err != nil {
		utils.ProblemDuplicate(c, "Voice name")
		return
	}

	// Create voice
	result, err := h.db.ExecContext(c.Request.Context(), "INSERT INTO voices (name) VALUES (?)", req.Name)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to create voice")
		return
	}

	id, _ := result.LastInsertId()
	utils.CreatedWithID(c, id, "Voice created successfully")
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

	// Check if voice exists
	if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", id) {
		return
	}

	// Check name uniqueness (excluding current record)
	if err := utils.CheckUnique(h.db, "voices", "name", req.Name, &id); err != nil {
		utils.ProblemDuplicate(c, "Voice name")
		return
	}

	// Update voice
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE voices SET name = ? WHERE id = ?", req.Name, id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to update voice")
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

	// Check for dependencies
	count, err := utils.CountDependencies(h.db, "stories", "voice_id", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, "Cannot delete voice: it is used by stories")
		return
	}

	// Check station_voices dependencies
	count, err = utils.CountDependencies(h.db, "station_voices", "voice_id", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, "Cannot delete voice: it is used by stations")
		return
	}

	// Delete voice
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM voices WHERE id = ?", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to delete voice")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.ProblemNotFound(c, "Voice")
		return
	}

	utils.NoContent(c)
}
