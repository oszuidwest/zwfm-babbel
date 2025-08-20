package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StoryResponse represents the response format for stories
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
	WeekdaysMap     map[string]bool `json:"weekdays"`
}

// GetStoryAudioURL returns the API URL for downloading a story's audio file, or nil if no audio.
func GetStoryAudioURL(storyID int, hasAudio bool) *string {
	if !hasAudio {
		return nil
	}
	url := fmt.Sprintf("/api/v1/stories/%d/audio", storyID)
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
						(*stories)[i].WeekdaysMap = weekdaysFromStoryResponse(&(*stories)[i])
					}
				}
			},
		},
		SearchFields:  []string{"s.title", "s.text", "v.name"},
		TableAlias:    "s",
		DefaultFields: "s.*, COALESCE(v.name, '') as voice_name",
		FieldMapping: map[string]string{
			"id":            "s.id",
			"title":         "s.title",
			"text":          "s.text",
			"voice_id":      "s.voice_id",
			"voice_name":    "COALESCE(v.name, '')",
			"status":        "s.status",
			"start_date":    "s.start_date",
			"end_date":      "s.end_date",
			"created_at":    "s.created_at",
			"updated_at":    "s.updated_at",
			"deleted_at":    "s.deleted_at",
			"audio_file":    "s.audio_file",
			"monday":        "s.monday",
			"tuesday":       "s.tuesday",
			"wednesday":     "s.wednesday",
			"thursday":      "s.thursday",
			"friday":        "s.friday",
			"saturday":      "s.saturday",
			"sunday":        "s.sunday",
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
	story.WeekdaysMap = weekdaysFromStoryResponse(&story)

	utils.Success(c, story)
}

// CreateStory creates a new story with optional audio upload
func (h *Handlers) CreateStory(c *gin.Context) {
	// Parse form data and collect validation errors
	var validationErrors []utils.ValidationError

	title := c.PostForm("title")
	if title == "" {
		validationErrors = append(validationErrors, utils.ValidationError{
			Field:   "title",
			Message: "Title is required",
		})
	}

	text := c.PostForm("text")
	if text == "" {
		validationErrors = append(validationErrors, utils.ValidationError{
			Field:   "text",
			Message: "Text is required",
		})
	}

	status := c.PostForm("status")
	if status == "" {
		status = "draft"
	}
	if status != "draft" && status != "active" && status != "expired" {
		validationErrors = append(validationErrors, utils.ValidationError{
			Field:   "status",
			Message: "Status must be one of: draft, active, expired",
		})
	}

	// Return validation errors if any
	if len(validationErrors) > 0 {
		utils.ProblemValidationError(c, "The request contains invalid data", validationErrors)
		return
	}

	// Parse voice ID (optional)
	voiceID, err := utils.ParseOptionalIntForm(c, "voice_id")
	if err != nil {
		utils.ProblemValidationError(c, "Invalid voice_id parameter", []utils.ValidationError{
			{Field: "voice_id", Message: err.Error()},
		})
		return
	}
	if voiceID != nil {
		if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", *voiceID) {
			return
		}
	}

	// Parse dates (required for story creation)
	startDate, ok := utils.ParseRequiredFormDate(c, "start_date", "Start date")
	if !ok {
		return
	}
	endDate, ok := utils.ParseRequiredFormDate(c, "end_date", "End date")
	if !ok {
		return
	}

	// Parse weekdays from individual form fields
	monday := utils.ParseBoolForm(c, "monday", false)
	tuesday := utils.ParseBoolForm(c, "tuesday", false)
	wednesday := utils.ParseBoolForm(c, "wednesday", false)
	thursday := utils.ParseBoolForm(c, "thursday", false)
	friday := utils.ParseBoolForm(c, "friday", false)
	saturday := utils.ParseBoolForm(c, "saturday", false)
	sunday := utils.ParseBoolForm(c, "sunday", false)

	metadata := c.PostForm("metadata")
	// Handle empty metadata - MySQL JSON column requires NULL not empty string
	var metadataValue interface{}
	if metadata == "" {
		metadataValue = nil
	} else {
		metadataValue = metadata
	}

	// Validate title length (MySQL column is VARCHAR(500))
	if len(title) > 500 {
		utils.ProblemBadRequest(c, "Title is too long (maximum 500 characters)")
		return
	}

	// Create story
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stories (title, text, voice_id, status, start_date, end_date, monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		title, text, voiceID, status, startDate, endDate, monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadataValue)
	if err != nil {
		logger.Error("Database error creating story: %v", err)
		// Provide more specific error messages for common database errors
		if strings.Contains(err.Error(), "Data too long") {
			utils.ProblemBadRequest(c, "One or more fields exceed maximum length")
		} else if strings.Contains(err.Error(), "Duplicate entry") {
			utils.ProblemDuplicate(c, "Story")
		} else if strings.Contains(err.Error(), "foreign key constraint") {
			utils.ProblemBadRequest(c, "Invalid reference to related resource")
		} else {
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
			utils.ProblemBadRequest(c, err.Error())
			return
		}
		defer cleanup()

		// Process audio with audio service
		if _, _, err := h.audioSvc.ConvertStoryToWAV(c.Request.Context(), int(storyID), tempPath); err != nil {
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

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	// Check if this is JSON input or form data
	contentType := c.GetHeader("Content-Type")
	isJSON := strings.Contains(contentType, "application/json")

	if isJSON {
		// Handle JSON input for PUT requests
		var req struct {
			Title     *string                `json:"title,omitempty"`
			Text      *string                `json:"text,omitempty"`
			Status    *string                `json:"status,omitempty"`
			VoiceID   *int                   `json:"voice_id,omitempty"`
			StartDate *string                `json:"start_date,omitempty"`
			EndDate   *string                `json:"end_date,omitempty"`
			Weekdays  map[string]bool        `json:"weekdays,omitempty"`
			Metadata  *string                `json:"metadata,omitempty"`
		}

		if !utils.BindAndValidate(c, &req) {
			return
		}

		// Process JSON fields
		if req.Title != nil {
			if len(*req.Title) > 500 {
				utils.ProblemBadRequest(c, "Title is too long (maximum 500 characters)")
				return
			}
			updates = append(updates, "title = ?")
			args = append(args, *req.Title)
		}

		if req.Text != nil {
			updates = append(updates, "text = ?")
			args = append(args, *req.Text)
		}

		if req.Status != nil {
			if *req.Status != "draft" && *req.Status != "active" && *req.Status != "expired" {
				utils.ProblemBadRequest(c, "Status must be one of: draft, active, expired")
				return
			}
			updates = append(updates, "status = ?")
			args = append(args, *req.Status)
		}

		if req.VoiceID != nil {
			if *req.VoiceID <= 0 {
				utils.ProblemBadRequest(c, "Valid voice_id is required")
				return
			}
			if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", *req.VoiceID) {
				return
			}
			updates = append(updates, "voice_id = ?")
			args = append(args, *req.VoiceID)
		}

		if req.StartDate != nil {
			if startDate, err := time.Parse("2006-01-02", *req.StartDate); err != nil {
				utils.ProblemBadRequest(c, "Invalid start_date format, use YYYY-MM-DD")
				return
			} else {
				updates = append(updates, "start_date = ?")
				args = append(args, startDate)
			}
		}

		if req.EndDate != nil {
			if endDate, err := time.Parse("2006-01-02", *req.EndDate); err != nil {
				utils.ProblemBadRequest(c, "Invalid end_date format, use YYYY-MM-DD")
				return
			} else {
				updates = append(updates, "end_date = ?")
				args = append(args, endDate)
			}
		}

		if req.Weekdays != nil {
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
		}

		if req.Metadata != nil {
			updates = append(updates, "metadata = ?")
			if *req.Metadata == "" {
				args = append(args, nil)
			} else {
				args = append(args, *req.Metadata)
			}
		}
	} else {
		// Handle form data (existing logic for file uploads)
		if title := c.PostForm("title"); title != "" {
			// Validate title length (MySQL column is VARCHAR(500))
			if len(title) > 500 {
				utils.ProblemBadRequest(c, "Title is too long (maximum 500 characters)")
				return
			}
			updates = append(updates, "title = ?")
			args = append(args, title)
		}

		if text := c.PostForm("text"); text != "" {
			updates = append(updates, "text = ?")
			args = append(args, text)
		}

		if status := c.PostForm("status"); status != "" {
			if status != "draft" && status != "active" && status != "expired" {
				utils.ProblemBadRequest(c, "Status must be one of: draft, active, expired")
				return
			}
			updates = append(updates, "status = ?")
			args = append(args, status)
		}

		if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
			voiceID, err := strconv.Atoi(voiceIDStr)
			if err != nil || voiceID <= 0 {
				utils.ProblemBadRequest(c, "Valid voice_id is required")
				return
			}
			if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", voiceID) {
				return
			}
			updates = append(updates, "voice_id = ?")
			args = append(args, voiceID)
		}

		if startDate, ok := utils.ParseFormDate(c, "start_date", "start date"); ok && !startDate.IsZero() {
			updates = append(updates, "start_date = ?")
			args = append(args, startDate)
		}

		if endDate, ok := utils.ParseFormDate(c, "end_date", "end date"); ok && !endDate.IsZero() {
			updates = append(updates, "end_date = ?")
			args = append(args, endDate)
		}

		// Handle weekdays - check for individual fields or JSON object
		weekdayFields := []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}
		hasWeekdayUpdate := false
		weekdayValues := make([]interface{}, 7)
		
		// Check for individual weekday fields
		for i, day := range weekdayFields {
			if _, exists := c.Request.PostForm[day]; exists {
				hasWeekdayUpdate = true
				value := c.PostForm(day)
				weekdayValues[i] = value == "true" || value == "1"
			}
		}
		
		// Check for weekdays JSON object (overrides individual fields if present)
		if weekdaysStr := c.PostForm("weekdays"); weekdaysStr != "" {
			var weekdaysMap map[string]bool
			if err := json.Unmarshal([]byte(weekdaysStr), &weekdaysMap); err != nil {
				utils.ProblemBadRequest(c, "Invalid weekdays format - must be valid JSON")
				return
			}
			hasWeekdayUpdate = true
			for i, day := range weekdayFields {
				weekdayValues[i] = weekdaysMap[day]
			}
		}
		
		if hasWeekdayUpdate {
			updates = append(updates, "monday = ?, tuesday = ?, wednesday = ?, thursday = ?, friday = ?, saturday = ?, sunday = ?")
			args = append(args, weekdayValues...)
		}

		// Check if metadata field was provided (could be empty string to set NULL)
		if _, exists := c.Request.PostForm["metadata"]; exists {
			metadata := c.PostForm("metadata")
			updates = append(updates, "metadata = ?")
			// Handle JSON column - empty string should be NULL
			if metadata == "" {
				args = append(args, nil)
			} else {
				args = append(args, metadata)
			}
		}
	}

	if len(updates) == 0 {
		utils.ProblemBadRequest(c, "No fields to update")
		return
	}

	// Execute update
	query := "UPDATE stories SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
		logger.Error("Database error updating story: %v", err)
		// Provide more specific error messages for common database errors
		if strings.Contains(err.Error(), "Data too long") {
			utils.ProblemBadRequest(c, "One or more fields exceed maximum length")
		} else if strings.Contains(err.Error(), "Duplicate entry") {
			utils.ProblemDuplicate(c, "Story")
		} else if strings.Contains(err.Error(), "foreign key constraint") {
			utils.ProblemBadRequest(c, "Invalid reference to related resource")
		} else {
			utils.ProblemInternalServer(c, "Failed to update story due to database error")
		}
		return
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
		utils.ProblemBadRequest(c, "At least one field (status or deleted_at) is required")
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
			utils.ProblemBadRequest(c, "Status must be one of: draft, active, expired")
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
