// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryResponse represents the response format for news stories with computed weekday information.
// Includes all story metadata, scheduling configuration, and optional voice/audio associations.
// The Weekdays field is computed from individual weekday boolean fields for client convenience.
type StoryResponse struct {
	ID              int             `json:"id" db:"id"`
	Title           string          `json:"title" db:"title"`
	Text            string          `json:"text" db:"text"`
	VoiceID         *int            `json:"voice_id" db:"voice_id"`
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
func GetStoryAudioURL(storyID int, hasAudio bool) *string {
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
			PostProcessor: func(result interface{}) {
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
	utils.ModernListWithQuery(c, h.db, config, &stories)
}

// GetStory returns a single story by ID
func (h *Handlers) GetStory(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var story StoryResponse
	query := utils.BuildStoryQuery("s.id = ?", true)
	if err := h.db.Get(&story, query, id); err != nil {
		if err == sql.ErrNoRows {
			utils.ProblemNotFound(c, "Story")
		} else {
			utils.ProblemInternalServer(c, "Failed to fetch story")
		}
		return
	}

	// Add audio URL and weekdays map
	hasAudio := story.AudioFile != ""
	story.AudioURL = GetStoryAudioURL(story.ID, hasAudio)
	story.Weekdays = weekdaysFromStoryResponse(&story)

	utils.Success(c, story)
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
		req.Status = "draft"
	}

	// Validate voice exists if provided
	if req.VoiceID != nil {
		if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", *req.VoiceID) {
			return
		}
	}

	// Handle weekdays from JSON if provided, otherwise use individual form fields
	var monday, tuesday, wednesday, thursday, friday, saturday, sunday bool
	if len(req.Weekdays) > 0 {
		// Use weekdays map from JSON
		monday = req.Weekdays["monday"]
		tuesday = req.Weekdays["tuesday"]
		wednesday = req.Weekdays["wednesday"]
		thursday = req.Weekdays["thursday"]
		friday = req.Weekdays["friday"]
		saturday = req.Weekdays["saturday"]
		sunday = req.Weekdays["sunday"]
	} else {
		// Use individual form fields
		monday = req.Monday
		tuesday = req.Tuesday
		wednesday = req.Wednesday
		thursday = req.Thursday
		friday = req.Friday
		saturday = req.Saturday
		sunday = req.Sunday
	}

	// Parse dates for database storage
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		// This should not happen due to validation, but handle gracefully
		utils.ProblemValidationError(c, "Date validation failed", []utils.ValidationError{
			{Field: "start_date", Message: "Invalid start date format"},
		})
		return
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		// This should not happen due to validation, but handle gracefully
		utils.ProblemValidationError(c, "Date validation failed", []utils.ValidationError{
			{Field: "end_date", Message: "Invalid end date format"},
		})
		return
	}

	// Handle metadata - MySQL JSON column requires NULL not empty string
	var metadataValue interface{}
	if req.Metadata == nil || *req.Metadata == "" {
		metadataValue = nil
	} else {
		metadataValue = *req.Metadata
	}

	// Create story
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stories (title, text, voice_id, status, start_date, end_date, monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		req.Title, req.Text, req.VoiceID, req.Status, startDate, endDate, monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadataValue)
	if err != nil {
		logger.Error("Database error creating story: %v", err)
		// Provide more specific error messages for common database errors
		errStr := err.Error()
		switch {
		case strings.Contains(errStr, "Data too long"):
			utils.ProblemValidationError(c, "Data validation failed", []utils.ValidationError{
				{Field: "data", Message: "One or more fields exceed maximum length"},
			})
		case strings.Contains(errStr, "Duplicate entry"):
			utils.ProblemDuplicate(c, "Story")
		case strings.Contains(errStr, "foreign key constraint"):
			utils.ProblemBadRequest(c, "Invalid reference to related resource")
		default:
			utils.ProblemInternalServer(c, "Failed to create story due to database error")
		}
		return
	}

	storyID, _ := result.LastInsertId()

	// Handle optional audio file upload
	_, _, err = c.Request.FormFile("audio")
	if err == nil {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", storyID))
		if err != nil {
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "audio",
				Message: err.Error(),
			}})
			return
		}
		defer cleanup()

		// Process audio with audio service (convert to mono WAV)
		outputPath := utils.GetStoryPath(h.config, int(storyID))
		if _, _, err := h.audioSvc.ConvertToWAV(c.Request.Context(), tempPath, outputPath, 1); err != nil {
			logger.Error("Failed to process story audio: %v", err)
			utils.ProblemInternalServer(c, "Failed to process audio")
			return
		}

		// Update database with relative audio path
		relativePath := utils.GetStoryRelativePath(h.config, int(storyID))
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE stories SET audio_file = ? WHERE id = ?", relativePath, storyID)
		if err != nil {
			utils.ProblemInternalServer(c, "Failed to update audio reference")
			return
		}
	}

	utils.CreatedWithID(c, storyID, "Story created successfully")
}

// UpdateStory updates an existing story
func (h *Handlers) UpdateStory(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	if !utils.ValidateResourceExists(c, h.db, "stories", "Story", id) {
		return
	}

	var req utils.StoryUpdateRequest

	// Bind and validate the request using our unified validation
	if !utils.BindFormAndValidate(c, &req) {
		return
	}

	// Validate date range if both dates provided
	if !h.validateDateRange(c, req.StartDate, req.EndDate) {
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	// Handle each field that may be updated
	if req.Title != nil {
		updates = append(updates, "title = ?")
		args = append(args, *req.Title)
	}

	if req.Text != nil {
		updates = append(updates, "text = ?")
		args = append(args, *req.Text)
	}

	if req.Status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *req.Status)
	}

	if req.VoiceID != nil {
		if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", *req.VoiceID) {
			return
		}
		updates = append(updates, "voice_id = ?")
		args = append(args, *req.VoiceID)
	}

	if req.StartDate != nil {
		startDate, _ := time.Parse("2006-01-02", *req.StartDate) // Already validated above
		updates = append(updates, "start_date = ?")
		args = append(args, startDate)
	}

	if req.EndDate != nil {
		endDate, _ := time.Parse("2006-01-02", *req.EndDate) // Already validated above
		updates = append(updates, "end_date = ?")
		args = append(args, endDate)
	}

	// Handle weekdays updates - either from weekdays map or individual fields
	if len(req.Weekdays) > 0 {
		// Use weekdays map if provided
		updates = append(updates, "monday = ?, tuesday = ?, wednesday = ?, thursday = ?, friday = ?, saturday = ?, sunday = ?")
		args = append(args,
			req.Weekdays["monday"],
			req.Weekdays["tuesday"],
			req.Weekdays["wednesday"],
			req.Weekdays["thursday"],
			req.Weekdays["friday"],
			req.Weekdays["saturday"],
			req.Weekdays["sunday"],
		)
	} else {
		// Update individual weekday fields if provided
		weekdayFields := map[string]*bool{
			"monday": req.Monday, "tuesday": req.Tuesday, "wednesday": req.Wednesday,
			"thursday": req.Thursday, "friday": req.Friday, "saturday": req.Saturday, "sunday": req.Sunday,
		}
		for field, value := range weekdayFields {
			if value != nil {
				updates = append(updates, field+" = ?")
				args = append(args, *value)
			}
		}
	}

	if req.Metadata != nil {
		updates = append(updates, "metadata = ?")
		// Handle JSON column - empty string should be NULL
		if *req.Metadata == "" {
			args = append(args, nil)
		} else {
			args = append(args, *req.Metadata)
		}
	}

	// Check if there's an audio file to process
	hasAudioUpdate := false
	_, _, err := c.Request.FormFile("audio")
	if err == nil {
		hasAudioUpdate = true
	}

	if len(updates) == 0 && !hasAudioUpdate {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "fields",
			Message: "No fields to update",
		}})
		return
	}

	// Execute database update if there are field updates
	if len(updates) > 0 {
		query := "UPDATE stories SET " + strings.Join(updates, ", ") + " WHERE id = ?"
		args = append(args, id)

		if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
			logger.Error("Database error updating story: %v", err)
			// Provide more specific error messages for common database errors
			errStr := err.Error()
			switch {
			case strings.Contains(errStr, "Data too long"):
				utils.ProblemValidationError(c, "Data validation failed", []utils.ValidationError{
					{Field: "data", Message: "One or more fields exceed maximum length"},
				})
			case strings.Contains(errStr, "Duplicate entry"):
				utils.ProblemDuplicate(c, "Story")
			case strings.Contains(errStr, "foreign key constraint"):
				utils.ProblemBadRequest(c, "Invalid reference to related resource")
			default:
				utils.ProblemInternalServer(c, "Failed to update story due to database error")
			}
			return
		}
	}

	// Handle audio file replacement if provided
	if hasAudioUpdate {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", id))
		if err != nil {
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "audio",
				Message: err.Error(),
			}})
			return
		}
		defer cleanup()

		// Process audio with audio service (convert to mono WAV)
		outputPath := utils.GetStoryPath(h.config, id)
		if _, _, err := h.audioSvc.ConvertToWAV(c.Request.Context(), tempPath, outputPath, 1); err != nil {
			logger.Error("Failed to process story audio: %v", err)
			utils.ProblemInternalServer(c, "Failed to process audio")
			return
		}

		// Update database with relative audio path
		relativePath := utils.GetStoryRelativePath(h.config, id)
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE stories SET audio_file = ? WHERE id = ?", relativePath, id)
		if err != nil {
			logger.Error("Failed to update audio reference: %v", err)
			utils.ProblemInternalServer(c, "Failed to update audio reference")
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
	if !utils.ValidateResourceExists(c, h.db, "stories", "Story", id) {
		return
	}
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error deleting story: %v", err)
		utils.ProblemInternalServer(c, "Failed to delete story due to database error")
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
	if !utils.ValidateResourceExists(c, h.db, "stories", "Story", id) {
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

	// Validate status field if provided
	if req.Status != nil {
		validStatuses := []string{"draft", "active", "expired"}
		isValid := false
		for _, validStatus := range validStatuses {
			if *req.Status == validStatus {
				isValid = true
				break
			}
		}
		if !isValid {
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "status",
				Message: "Status must be one of: draft, active, expired",
			}})
			return
		}
	}

	// Handle soft delete/restore
	if req.DeletedAt != nil {
		if *req.DeletedAt == "" {
			// Restore story (set deleted_at to NULL)
			_, err := h.db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NULL WHERE id = ?", id)
			if err != nil {
				logger.Error("Database error restoring story: %v", err)
				utils.ProblemInternalServer(c, "Failed to restore story due to database error")
				return
			}
			utils.SuccessWithMessage(c, "Story restored")
			return
		}
		// Soft delete story (set deleted_at to NOW())
		_, err := h.db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
		if err != nil {
			logger.Error("Database error soft deleting story: %v", err)
			utils.ProblemInternalServer(c, "Failed to soft delete story due to database error")
			return
		}
		utils.NoContent(c)
	}

	// Handle status update
	if req.Status != nil {
		_, err := h.db.ExecContext(c.Request.Context(), "UPDATE stories SET status = ? WHERE id = ?", *req.Status, id)
		if err != nil {
			logger.Error("Database error updating story status: %v", err)
			utils.ProblemInternalServer(c, "Failed to update story status due to database error")
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
