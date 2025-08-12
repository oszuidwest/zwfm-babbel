package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListVoices returns a paginated list of all newsreader voices available in the system.
func (h *Handlers) ListVoices(c *gin.Context) {
	var voices []models.Voice
	utils.GenericList(c, h.db, "voices", "*", &voices)
}

// GetVoice returns a single newsreader voice by ID with all its details.
func (h *Handlers) GetVoice(c *gin.Context) {
	var voice models.Voice
	utils.GenericGetByID(c, h.db, "voices", "Voice", &voice)
}

// CreateVoice creates a new newsreader voice with the provided name and validates uniqueness.
func (h *Handlers) CreateVoice(c *gin.Context) {
	var req utils.VoiceRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Check name uniqueness
	if err := utils.CheckUnique(h.db, "voices", "name", req.Name, nil); err != nil {
		utils.BadRequest(c, "Voice name already exists")
		return
	}

	// Create voice
	result, err := h.db.ExecContext(c.Request.Context(), "INSERT INTO voices (name) VALUES (?)", req.Name)
	if err != nil {
		utils.InternalServerError(c, "Failed to create voice")
		return
	}

	id, _ := result.LastInsertId()
	utils.CreatedWithID(c, id, "Voice created successfully")
}

// UpdateVoice updates an existing newsreader voice with new name while validating uniqueness.
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
		utils.BadRequest(c, "Voice name already exists")
		return
	}

	// Update voice
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE voices SET name = ? WHERE id = ?", req.Name, id)
	if err != nil {
		utils.InternalServerError(c, "Failed to update voice")
		return
	}

	utils.SuccessWithMessage(c, "Voice updated successfully")
}

// DeleteVoice deletes a newsreader voice if it has no dependencies like stories or station-voices.
func (h *Handlers) DeleteVoice(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check for dependencies
	count, err := utils.CountDependencies(h.db, "stories", "voice_id", id)
	if err != nil {
		utils.InternalServerError(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.BadRequest(c, "Cannot delete voice: it is used by stories")
		return
	}

	// Check station_voices dependencies
	count, err = utils.CountDependencies(h.db, "station_voices", "voice_id", id)
	if err != nil {
		utils.InternalServerError(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.BadRequest(c, "Cannot delete voice: it is used by stations")
		return
	}

	// Delete voice
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM voices WHERE id = ?", id)
	if err != nil {
		utils.InternalServerError(c, "Failed to delete voice")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.NotFound(c, "Voice")
		return
	}

	utils.NoContent(c)
}
