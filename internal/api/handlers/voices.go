package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListVoices returns a paginated list of newsreader voices.
func (h *Handlers) ListVoices(c *gin.Context) {
	query := utils.ParseListQuery(c)

	result, err := h.voiceSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// GetVoice returns a single newsreader voice by ID.
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

	utils.Success(c, voice)
}

// CreateVoice creates a new newsreader voice.
func (h *Handlers) CreateVoice(c *gin.Context) {
	var req utils.VoiceRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	voice, err := h.voiceSvc.Create(c.Request.Context(), req.Name, req.ElevenLabsVoiceID)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}

	utils.CreatedWithLocation(c, voice.ID, "/api/v1/voices", "Voice created successfully")
}

// UpdateVoice updates an existing newsreader voice.
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
		Name:              &req.Name,
		ElevenLabsVoiceID: req.ElevenLabsVoiceID,
	}

	updated, err := h.voiceSvc.Update(c.Request.Context(), id, updateReq)
	if err != nil {
		handleServiceError(c, err, "Voice")
		return
	}
	utils.Success(c, updated)
}

// DeleteVoice removes a newsreader voice.
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
