package handlers

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStories returns a paginated list of stories with modern query parameter support.
func (h *Handlers) ListStories(c *gin.Context) {
	params, ok := utils.ParseListQueryWithTrashed(c)
	if !ok {
		return
	}

	result, err := h.storySvc.List(c.Request.Context(), &params.ListQuery)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetStory returns a story by ID with computed fields populated by the model
// hooks used by the repository layer.
func (h *Handlers) GetStory(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	story, err := h.storySvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.Success(c, story)
}

// CreateStory accepts a JSON story payload and persists a scheduled story.
// Missing status defaults to draft and missing weekdays default to every day.
func (h *Handlers) CreateStory(c *gin.Context) {
	var req utils.StoryCreateRequest

	if !utils.BindJSON(c, &req) {
		return
	}

	if req.Status == "" {
		req.Status = string(models.StoryStatusDraft)
	}

	weekdays := models.Weekdays(req.Weekdays) // #nosec G115 - binding limits weekdays to 0-127
	if weekdays == 0 {
		weekdays = models.WeekdaysAll
	}

	svcReq := &services.CreateStoryRequest{
		Title:      req.Title,
		Text:       req.Text,
		VoiceID:    req.VoiceID,
		Status:     req.Status,
		StartDate:  req.StartDate,
		EndDate:    req.EndDate,
		Weekdays:   weekdays,
		IsBreaking: req.IsBreaking,
		Metadata:   req.Metadata,
	}

	story, err := h.storySvc.Create(c.Request.Context(), svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithLocation(c, story.ID, "/api/v1/stories", "Story created successfully")
}

// UpdateStory applies a JSON partial update to an existing story.
// Empty update objects are rejected before reaching the service layer.
func (h *Handlers) UpdateStory(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.StoryUpdateRequest
	if !utils.BindJSON(c, &req) {
		return
	}

	if !utils.RequireAnyField(c, req) {
		return
	}

	var weekdays *models.Weekdays
	if req.Weekdays != nil {
		w := models.Weekdays(*req.Weekdays) // #nosec G115 - binding limits weekdays to 0-127
		weekdays = &w
	}

	svcReq := &services.UpdateStoryRequest{
		Title:      req.Title,
		Text:       req.Text,
		VoiceID:    req.VoiceID,
		Status:     req.Status,
		StartDate:  req.StartDate,
		EndDate:    req.EndDate,
		Weekdays:   weekdays,
		IsBreaking: req.IsBreaking,
		Metadata:   req.Metadata,
	}

	updated, err := h.storySvc.Update(c.Request.Context(), id, svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.Success(c, updated)
}

// DeleteStory soft deletes a story.
func (h *Handlers) DeleteStory(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if err := h.storySvc.SoftDelete(c.Request.Context(), id); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.NoContent(c)
}

// UpdateStoryStatus changes workflow state or toggles soft deletion; a request
// sets exactly one of status and deleted_at. An empty deleted_at string
// restores the story; any non-empty deleted_at value is treated as a
// soft-delete request for compatibility with the legacy API.
func (h *Handlers) UpdateStoryStatus(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req struct {
		Status    *string `json:"status" binding:"omitempty,story_status"`
		DeletedAt *string `json:"deleted_at"`
	}
	if !utils.BindJSON(c, &req) {
		return
	}

	switch {
	case req.Status == nil && req.DeletedAt == nil:
		utils.ProblemValidationError(c, "The request contains invalid data", []apperrors.FieldError{{
			Field:   apperrors.FieldRequest,
			Code:    apperrors.CodeEmptyUpdate,
			Message: "Provide status or deleted_at",
		}})
		return
	case req.Status != nil && req.DeletedAt != nil:
		utils.ProblemValidationError(c, "The request contains invalid data", []apperrors.FieldError{{
			Field:   apperrors.FieldRequest,
			Code:    apperrors.CodeUnsupported,
			Message: "status and deleted_at cannot be combined",
		}})
		return
	}

	if req.DeletedAt != nil {
		if *req.DeletedAt == "" {
			if err := h.storySvc.Restore(c.Request.Context(), id); err != nil {
				handleServiceError(c, err, "Story")
				return
			}
			restored, err := h.storySvc.GetByID(c.Request.Context(), id)
			if err != nil {
				handleServiceError(c, err, "Story")
				return
			}
			utils.Success(c, restored)
			return
		}
		if err := h.storySvc.SoftDelete(c.Request.Context(), id); err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.NoContent(c)
		return
	}

	updated, err := h.storySvc.UpdateStatus(c.Request.Context(), id, *req.Status)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}
	utils.Success(c, updated)
}

// GenerateStoryTTS generates audio for a story using text-to-speech.
// Pass ?force=true to overwrite existing audio.
func (h *Handlers) GenerateStoryTTS(c *gin.Context) {
	if !h.requireTTSEnabled(c) {
		return
	}

	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	force := false
	if raw, present := c.GetQuery("force"); present {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			utils.ProblemQueryValidation(c, "Invalid query parameter", []apperrors.FieldError{{
				Field: "force", Code: apperrors.CodeInvalidFormat, Message: fmt.Sprintf("expected boolean, got %q", raw),
			}})
			return
		}
		force = parsed
	}

	if err := h.storySvc.GenerateTTS(c.Request.Context(), id, force); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithMessage(c, "TTS audio generated successfully")
}
