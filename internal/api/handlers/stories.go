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

// ListStories returns a filtered, sorted page of stories.
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

// GetStory returns a story with its voice and computed audio URL.
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
		ActorUserID: actorUserID(c),
		Title:       req.Title,
		Text:        req.Text,
		VoiceID:     req.VoiceID,
		Status:      req.Status,
		StartDate:   req.StartDate,
		EndDate:     req.EndDate,
		Weekdays:    weekdays,
		IsBreaking:  req.IsBreaking,
		Metadata:    req.Metadata,
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

	updated, err := h.storySvc.Update(c.Request.Context(), id, toStoryUpdateServiceRequest(req, actorUserID(c)))
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.Success(c, updated)
}

func toStoryUpdateServiceRequest(req utils.StoryUpdateRequest, actorUserID *int64) *services.UpdateStoryRequest {
	var weekdays *models.Weekdays
	if req.Weekdays != nil {
		w := models.Weekdays(*req.Weekdays) // #nosec G115 - binding limits weekdays to 0-127
		weekdays = &w
	}

	return &services.UpdateStoryRequest{
		ActorUserID: actorUserID,
		Title:       req.Title,
		Text:        req.Text,
		VoiceID:     req.VoiceID,
		Status:      req.Status,
		StartDate:   req.StartDate,
		EndDate:     req.EndDate,
		Weekdays:    weekdays,
		IsBreaking:  req.IsBreaking,
		Metadata:    req.Metadata,
	}
}

// DeleteStory soft deletes a story.
func (h *Handlers) DeleteStory(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if err := h.storySvc.SoftDelete(c.Request.Context(), id, actorUserID(c)); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.NoContent(c)
}

// UpdateStoryStatus changes status or soft deletion. Empty deleted_at restores
// atomically with optional story fields; any other value soft-deletes the story
// and accepts no other fields.
func (h *Handlers) UpdateStoryStatus(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req struct {
		utils.StoryUpdateRequest
		DeletedAt *string `json:"deleted_at"`
	}
	if !utils.BindJSON(c, &req) {
		return
	}

	if !utils.RequireAnyField(c, req) {
		return
	}

	fields := req.StoryUpdateRequest
	statusOnly := fields == utils.StoryUpdateRequest{Status: fields.Status}
	switch {
	case req.DeletedAt == nil && !statusOnly:
		utils.ProblemValidationError(c, "The request contains invalid data", apperrors.FieldError{
			Field:   apperrors.FieldRequest,
			Code:    apperrors.CodeUnsupported,
			Message: "Story fields other than status require deleted_at \"\" (restore); use PUT to update a story",
		})
	case req.DeletedAt == nil:
		updated, err := h.storySvc.Update(c.Request.Context(), id, toStoryUpdateServiceRequest(fields, actorUserID(c)))
		if err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.Success(c, updated)
	case *req.DeletedAt == "":
		restored, err := h.storySvc.Restore(c.Request.Context(), id, toStoryUpdateServiceRequest(fields, actorUserID(c)))
		if err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.Success(c, restored)
	case fields != utils.StoryUpdateRequest{}:
		utils.ProblemValidationError(c, "The request contains invalid data", apperrors.FieldError{
			Field:   apperrors.FieldRequest,
			Code:    apperrors.CodeUnsupported,
			Message: "A soft delete cannot be combined with other fields",
		})
	default:
		if err := h.storySvc.SoftDelete(c.Request.Context(), id, actorUserID(c)); err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.NoContent(c)
	}
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
			utils.ProblemQueryValidation(c, "Invalid query parameter", apperrors.FieldError{
				Field: "force", Code: apperrors.CodeInvalidFormat, Message: fmt.Sprintf("expected boolean, got %q", raw),
			})
			return
		}
		force = parsed
	}

	if err := h.storySvc.GenerateTTS(c.Request.Context(), id, force, actorUserID(c)); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithMessage(c, "TTS audio generated successfully")
}
