// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStories returns a paginated list of stories with modern query parameter support
func (h *Handlers) ListStories(c *gin.Context) {
	// Parse query parameters
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Convert to repository ListQuery
	query := convertToListQuery(params)

	// Call service
	result, err := h.storySvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	// Return stories directly - AfterFind hook populates computed fields
	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// GetStory returns a single story by ID
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

	// Return story directly - AfterFind hook populates computed fields
	utils.Success(c, story)
}

// CreateStory creates a new story (JSON API only)
func (h *Handlers) CreateStory(c *gin.Context) {
	var req utils.StoryCreateRequest

	// Pure JSON binding - no form-data support
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Apply default status if not provided
	if req.Status == "" {
		req.Status = string(models.StoryStatusDraft)
	}

	// Use provided weekdays or default to all days enabled
	weekdays := req.Weekdays
	if len(weekdays) == 0 {
		weekdays = models.WeekdaysAll.ToMap()
	}

	// Create service request
	svcReq := &services.CreateStoryRequest{
		Title:     req.Title,
		Text:      req.Text,
		VoiceID:   req.VoiceID,
		Status:    req.Status,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		Weekdays:  weekdays,
		Metadata:  req.Metadata,
	}

	// Create story via service
	story, err := h.storySvc.Create(c.Request.Context(), svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithID(c, story.ID, "Story created successfully")
}

// hasStoryFieldUpdates reports whether any story fields need updating.
func hasStoryFieldUpdates(req *utils.StoryUpdateRequest, weekdays map[string]bool) bool {
	return req.Title != nil || req.Text != nil || req.Status != nil ||
		req.VoiceID != nil || req.StartDate != nil || req.EndDate != nil ||
		len(weekdays) > 0 || req.Metadata != nil
}

// applyStoryFieldUpdates applies field updates via service
func (h *Handlers) applyStoryFieldUpdates(c *gin.Context, id int64, req *utils.StoryUpdateRequest, weekdays map[string]bool) bool {
	svcReq := &services.UpdateStoryRequest{
		Title:     req.Title,
		Text:      req.Text,
		VoiceID:   req.VoiceID,
		Status:    req.Status,
		StartDate: req.StartDate,
		EndDate:   req.EndDate,
		Weekdays:  weekdays,
		Metadata:  req.Metadata,
	}

	_, err := h.storySvc.Update(c.Request.Context(), id, svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return false
	}

	return true
}

// UpdateStory updates an existing story (JSON API only)
func (h *Handlers) UpdateStory(c *gin.Context) {
	// Get ID param
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Pure JSON binding - no form-data support
	var req utils.StoryUpdateRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Validate date range
	if !h.validateDateRange(c, req.StartDate, req.EndDate) {
		return
	}

	// Use weekdays directly from request (empty map means no weekday update)
	weekdays := req.Weekdays

	// Determine if there are field updates
	hasFieldUpdate := hasStoryFieldUpdates(&req, weekdays)

	// Validate update request - at least one field must be updated
	if !hasFieldUpdate {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return
	}

	// Apply field updates
	if !h.applyStoryFieldUpdates(c, id, &req, weekdays) {
		return
	}

	utils.SuccessWithMessage(c, "Story updated successfully")
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

// UpdateStoryStatus updates a story's status or handles soft delete/restore operations
func (h *Handlers) UpdateStoryStatus(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Support both status updates and soft delete/restore
	var req struct {
		Status    *string `json:"status"`
		DeletedAt *string `json:"deleted_at"`
	}
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Validate that at least one field is provided
	if req.Status == nil && req.DeletedAt == nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "request",
			Message: "At least one field (status or deleted_at) is required",
		}})
		return
	}

	// Handle soft delete/restore
	if req.DeletedAt != nil {
		if *req.DeletedAt == "" {
			// Restore story (set deleted_at to NULL)
			if err := h.storySvc.Restore(c.Request.Context(), id); err != nil {
				handleServiceError(c, err, "Story")
				return
			}
			utils.SuccessWithMessage(c, "Story restored")
			return
		}
		// Soft delete story (set deleted_at to NOW())
		if err := h.storySvc.SoftDelete(c.Request.Context(), id); err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.NoContent(c)
		return
	}

	// Handle status update
	if req.Status != nil {
		if err := h.storySvc.UpdateStatus(c.Request.Context(), id, *req.Status); err != nil {
			handleServiceError(c, err, "Story")
			return
		}
		utils.SuccessWithMessage(c, "Story status updated")
	}
}

// validateDateRange reports whether the date range is valid.
func (h *Handlers) validateDateRange(c *gin.Context, startDateStr, endDateStr *string) bool {
	if startDateStr == nil || endDateStr == nil {
		return true // Skip validation if either date is missing
	}

	startDate, err := time.Parse("2006-01-02", *startDateStr)
	if err != nil {
		utils.ProblemValidationError(c, "Date validation failed", []utils.ValidationError{
			{Field: "start_date", Message: "Invalid start date format"},
		})
		return false
	}

	endDate, err := time.Parse("2006-01-02", *endDateStr)
	if err != nil {
		utils.ProblemValidationError(c, "Date validation failed", []utils.ValidationError{
			{Field: "end_date", Message: "Invalid end date format"},
		})
		return false
	}

	if endDate.Before(startDate) {
		utils.ProblemValidationError(c, "Date validation failed", []utils.ValidationError{
			{Field: "end_date", Message: "End date cannot be before start date"},
		})
		return false
	}

	return true
}
