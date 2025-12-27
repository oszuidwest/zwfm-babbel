// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryResponse represents the response format for news stories with computed weekday information.
// Includes all story metadata, scheduling configuration, and optional voice/audio associations.
// The Weekdays field is computed from individual weekday boolean fields for client convenience.
type StoryResponse struct {
	ID              int64           `json:"id" db:"id"`
	Title           string          `json:"title" db:"title"`
	Text            string          `json:"text" db:"text"`
	VoiceID         *int64          `json:"voice_id" db:"voice_id"`
	AudioFile       string          `json:"-" db:"audio_file"`
	DurationSeconds *float64        `json:"duration_seconds" db:"duration_seconds"`
	Status          string          `json:"status" db:"status"`
	StartDate       time.Time       `json:"start_date" db:"start_date"`
	EndDate         time.Time       `json:"end_date" db:"end_date"`
	Monday          bool            `json:"-" db:"monday"`
	Tuesday         bool            `json:"-" db:"tuesday"`
	Wednesday       bool            `json:"-" db:"wednesday"`
	Thursday        bool            `json:"-" db:"thursday"`
	Friday          bool            `json:"-" db:"friday"`
	Saturday        bool            `json:"-" db:"saturday"`
	Sunday          bool            `json:"-" db:"sunday"`
	Metadata        *string         `json:"metadata" db:"metadata"`
	DeletedAt       *time.Time      `json:"deleted_at" db:"deleted_at"`
	CreatedAt       time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at" db:"updated_at"`
	VoiceName       string          `json:"voice_name" db:"voice_name"`
	AudioURL        *string         `json:"audio_url,omitempty"`
	Weekdays        map[string]bool `json:"weekdays,omitempty"`
}

// GetStoryAudioURL returns the API URL for downloading a story's audio file, or nil if no audio.
func GetStoryAudioURL(storyID int64, hasAudio bool) *string {
	if !hasAudio {
		return nil
	}
	url := fmt.Sprintf("/stories/%d/audio", storyID)
	return &url
}

// weekdaysFromStoryResponse converts StoryResponse weekday fields to map
func weekdaysFromStoryResponse(story *StoryResponse) map[string]bool {
	return map[string]bool{
		"monday":    story.Monday,
		"tuesday":   story.Tuesday,
		"wednesday": story.Wednesday,
		"thursday":  story.Thursday,
		"friday":    story.Friday,
		"saturday":  story.Saturday,
		"sunday":    story.Sunday,
	}
}

// modelStoryToResponse converts a models.Story to StoryResponse with computed fields
func modelStoryToResponse(story *models.Story) StoryResponse {
	response := StoryResponse{
		ID:              story.ID,
		Title:           story.Title,
		Text:            story.Text,
		VoiceID:         story.VoiceID,
		AudioFile:       story.AudioFile,
		DurationSeconds: story.DurationSeconds,
		Status:          story.Status.String(),
		StartDate:       story.StartDate,
		EndDate:         story.EndDate,
		Monday:          story.Monday,
		Tuesday:         story.Tuesday,
		Wednesday:       story.Wednesday,
		Thursday:        story.Thursday,
		Friday:          story.Friday,
		Saturday:        story.Saturday,
		Sunday:          story.Sunday,
		Metadata:        story.Metadata,
		DeletedAt:       story.DeletedAt,
		CreatedAt:       story.CreatedAt,
		UpdatedAt:       story.UpdatedAt,
		VoiceName:       story.VoiceName,
	}

	// Add computed fields
	hasAudio := story.AudioFile != ""
	response.AudioURL = GetStoryAudioURL(story.ID, hasAudio)
	response.Weekdays = story.GetWeekdaysMap()

	return response
}

// ListStories returns a paginated list of stories with modern query parameter support
func (h *Handlers) ListStories(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT s.*, COALESCE(v.name, '') as voice_name
			            FROM stories s 
			            LEFT JOIN voices v ON s.voice_id = v.id`,
			CountQuery:   "SELECT COUNT(*) FROM stories s LEFT JOIN voices v ON s.voice_id = v.id",
			DefaultOrder: "s.created_at DESC",
			PostProcessor: func(result any) {
				// Post-process stories to add audio URLs and weekdays map
				if stories, ok := result.(*[]StoryResponse); ok {
					for i := range *stories {
						hasAudio := (*stories)[i].AudioFile != ""
						(*stories)[i].AudioURL = GetStoryAudioURL((*stories)[i].ID, hasAudio)
						(*stories)[i].Weekdays = weekdaysFromStoryResponse(&(*stories)[i])
					}
				}
			},
		},
		SearchFields:  []string{"s.title", "s.text", "v.name"},
		TableAlias:    "s",
		DefaultFields: "s.*, COALESCE(v.name, '') as voice_name",
		FieldMapping: map[string]string{
			"id":         "s.id",
			"title":      "s.title",
			"text":       "s.text",
			"voice_id":   "s.voice_id",
			"voice_name": "COALESCE(v.name, '')",
			"status":     "s.status",
			"start_date": "s.start_date",
			"end_date":   "s.end_date",
			"created_at": "s.created_at",
			"updated_at": "s.updated_at",
			"deleted_at": "s.deleted_at",
			"audio_file": "s.audio_file",
			"monday":     "s.monday",
			"tuesday":    "s.tuesday",
			"wednesday":  "s.wednesday",
			"thursday":   "s.thursday",
			"friday":     "s.friday",
			"saturday":   "s.saturday",
			"sunday":     "s.sunday",
		},
	}

	var stories []StoryResponse
	utils.ModernListWithQuery(c, h.storySvc.DB(), config, &stories)
}

// GetStory returns a single story by ID
func (h *Handlers) GetStory(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	story, err := h.storySvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	response := modelStoryToResponse(story)
	utils.Success(c, response)
}

// CreateStory creates a new story with optional audio upload
func (h *Handlers) CreateStory(c *gin.Context) {
	var req utils.StoryCreateRequest

	// Bind and validate the request using our unified validation
	if !utils.BindFormAndValidate(c, &req) {
		return
	}

	// Apply default status if not provided
	if req.Status == "" {
		req.Status = string(models.StoryStatusDraft)
	}

	// Handle weekdays from JSON if provided, otherwise use individual form fields
	weekdays := req.Weekdays
	if len(weekdays) == 0 {
		// Build from individual form fields
		weekdays = map[string]bool{
			"monday":    req.Monday,
			"tuesday":   req.Tuesday,
			"wednesday": req.Wednesday,
			"thursday":  req.Thursday,
			"friday":    req.Friday,
			"saturday":  req.Saturday,
			"sunday":    req.Sunday,
		}
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
		Metadata:  nil, // Metadata not yet supported in service
	}

	// Create story via service
	story, err := h.storySvc.Create(c.Request.Context(), svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	// Handle optional audio file upload
	_, _, err = c.Request.FormFile("audio")
	if err == nil {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", story.ID))
		if err != nil {
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "audio",
				Message: err.Error(),
			}})
			return
		}
		defer func() {
			if err := cleanup(); err != nil {
				logger.Error("Failed to cleanup audio file: %v", err)
			}
		}()

		// Process audio via service
		if err := h.storySvc.ProcessAudio(c.Request.Context(), story.ID, tempPath); err != nil {
			handleServiceError(c, err, "Story")
			return
		}
	}

	utils.CreatedWithID(c, story.ID, "Story created successfully")
}

// hasAnyIndividualWeekday checks if any individual weekday field is set in the request
func hasAnyIndividualWeekday(req *utils.StoryUpdateRequest) bool {
	return req.Monday != nil || req.Tuesday != nil || req.Wednesday != nil ||
		req.Thursday != nil || req.Friday != nil || req.Saturday != nil || req.Sunday != nil
}

// applyWeekdayUpdates updates the weekdays map with values from individual request fields
func applyWeekdayUpdates(weekdays map[string]bool, req *utils.StoryUpdateRequest) {
	weekdayFields := []struct {
		name  string
		value *bool
	}{
		{"monday", req.Monday},
		{"tuesday", req.Tuesday},
		{"wednesday", req.Wednesday},
		{"thursday", req.Thursday},
		{"friday", req.Friday},
		{"saturday", req.Saturday},
		{"sunday", req.Sunday},
	}

	for _, field := range weekdayFields {
		if field.value != nil {
			weekdays[field.name] = *field.value
		}
	}
}

// processWeekdaysUpdate handles weekday merging logic for story updates
func (h *Handlers) processWeekdaysUpdate(c *gin.Context, id int64, req *utils.StoryUpdateRequest) (map[string]bool, error) {
	// Handle weekdays - either from weekdays map or individual fields
	if len(req.Weekdays) > 0 {
		return req.Weekdays, nil
	}

	// Build from individual fields if any are provided
	if !hasAnyIndividualWeekday(req) {
		return nil, nil
	}

	// Need to fetch current story to preserve unspecified weekdays
	current, err := h.storySvc.GetByID(c.Request.Context(), id)
	if err != nil {
		return nil, err
	}

	weekdays := current.GetWeekdaysMap()
	applyWeekdayUpdates(weekdays, req)

	return weekdays, nil
}

// hasStoryFieldUpdates checks if any story fields need updating
func hasStoryFieldUpdates(req *utils.StoryUpdateRequest, weekdays map[string]bool) bool {
	return req.Title != nil || req.Text != nil || req.Status != nil ||
		req.VoiceID != nil || req.StartDate != nil || req.EndDate != nil ||
		len(weekdays) > 0 || req.Metadata != nil
}

// validateStoryUpdateRequest validates that at least one field or audio is being updated
func validateStoryUpdateRequest(c *gin.Context, hasFieldUpdate, hasAudioUpdate bool) bool {
	if !hasFieldUpdate && !hasAudioUpdate {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return false
	}
	return true
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
		Metadata:  nil, // Metadata not yet supported in service
	}

	_, err := h.storySvc.Update(c.Request.Context(), id, svcReq)
	if err != nil {
		handleServiceError(c, err, "Story")
		return false
	}

	return true
}

// processStoryAudioUpdate handles audio file processing
func (h *Handlers) processStoryAudioUpdate(c *gin.Context, id int64) bool {
	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", id))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "audio",
			Message: err.Error(),
		}})
		return false
	}
	defer func() {
		if err := cleanup(); err != nil {
			logger.Error("Failed to cleanup audio file: %v", err)
		}
	}()

	// Process audio via service
	if err := h.storySvc.ProcessAudio(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Story")
		return false
	}

	return true
}

// UpdateStory updates an existing story
func (h *Handlers) UpdateStory(c *gin.Context) {
	// Get ID param
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Bind request
	var req utils.StoryUpdateRequest
	if !utils.BindFormAndValidate(c, &req) {
		return
	}

	// Validate date range
	if !h.validateDateRange(c, req.StartDate, req.EndDate) {
		return
	}

	// Process weekdays
	weekdays, err := h.processWeekdaysUpdate(c, id, &req)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	// Check for audio update
	_, _, err = c.Request.FormFile("audio")
	hasAudioUpdate := err == nil

	// Determine if there are field updates
	hasFieldUpdate := hasStoryFieldUpdates(&req, weekdays)

	// Validate update request
	if !validateStoryUpdateRequest(c, hasFieldUpdate, hasAudioUpdate) {
		return
	}

	// Apply field updates if needed
	if hasFieldUpdate {
		if !h.applyStoryFieldUpdates(c, id, &req, weekdays) {
			return
		}
	}

	// Process audio if needed
	if hasAudioUpdate {
		if !h.processStoryAudioUpdate(c, id) {
			return
		}
	}

	utils.SuccessWithMessage(c, "Story updated successfully")
}

// DeleteStory soft deletes a story by setting deleted_at timestamp
func (h *Handlers) DeleteStory(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
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
	id, ok := utils.GetIDParam(c)
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

// validateDateRange validates start and end dates if both are provided
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
