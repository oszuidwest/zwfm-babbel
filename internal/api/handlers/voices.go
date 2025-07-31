package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// VoiceInput represents the request parameters for creating or updating a voice.
type VoiceInput struct {
	Name string `json:"name" binding:"required"`
}

// ListVoices returns a paginated list of all voices.
func (h *Handlers) ListVoices(c *gin.Context) {
	crud := NewCRUDHandler(h.db, "voices", WithOrderBy("name ASC"))

	var voices []models.Voice
	filters := map[string]string{}

	total, err := crud.List(c, &voices, filters)
	if err != nil {
		responses.InternalServerError(c, err.Error())
		return
	}

	limit, offset := extractPaginationParams(c)
	responses.Paginated(c, voices, total, limit, offset)
}

// GetVoice returns a single voice by ID.
func (h *Handlers) GetVoice(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "voice")
	if !ok {
		return
	}

	crud := NewCRUDHandler(h.db, "voices")
	var voice models.Voice
	crud.GetByID(c, id, &voice)
}

// CreateVoice creates a new voice.
func (h *Handlers) CreateVoice(c *gin.Context) {
	var input VoiceInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Create voice (without jingle - jingles are station-specific)
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO voices (name) VALUES (?)",
		input.Name,
	)
	if err != nil {
		responses.InternalServerError(c, "Failed to create voice")
		return
	}

	voiceID, err := result.LastInsertId()
	if err != nil {
		responses.InternalServerError(c, "Failed to get voice ID")
		return
	}

	// Fetch the created voice
	var voice models.Voice
	h.fetchAndRespond(c, "SELECT * FROM voices WHERE id = ?", voiceID, &voice, true)
}

// UpdateVoice updates an existing voice.
func (h *Handlers) UpdateVoice(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "voice")
	if !ok {
		return
	}

	var input VoiceInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Check if voice exists
	if !h.validateRecordExists(c, "voices", "Voice", id) {
		return
	}

	// Update voice name
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE voices SET name = ? WHERE id = ?", input.Name, id)
	if err != nil {
		responses.InternalServerError(c, "Failed to update voice")
		return
	}

	// Fetch updated voice
	var voice models.Voice
	h.fetchAndRespond(c, "SELECT * FROM voices WHERE id = ?", id, &voice, false)
}

// DeleteVoice deletes a voice if it has no dependencies.
func (h *Handlers) DeleteVoice(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "voice")
	if !ok {
		return
	}

	crud := NewCRUDHandler(h.db, "voices")
	checks := []DependencyCheck{
		{
			Query:        "SELECT COUNT(*) FROM stories WHERE voice_id = ?",
			ErrorMessage: "Cannot delete voice: %d stories are still using this voice",
		},
	}
	crud.DeleteWithCheck(c, id, checks)
}
