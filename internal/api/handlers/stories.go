package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/api/validation"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// GetStoryAudioURL returns the API URL for a story's audio file, or nil if no audio exists.
func GetStoryAudioURL(storyID int, hasAudio bool) *string {
	if !hasAudio {
		return nil
	}
	url := fmt.Sprintf("/api/v1/stories/%d/audio", storyID)
	return &url
}

// storyToResponse converts a story model to API response format
func storyToResponse(story models.Story) map[string]interface{} {
	response := map[string]interface{}{
		"id":               story.ID,
		"title":            story.Title,
		"text":             story.Text,
		"voice_id":         story.VoiceID,
		"audio_url":        GetStoryAudioURL(story.ID, story.AudioFile != ""),
		"duration_seconds": story.DurationSeconds,
		"status":           story.Status,
		"start_date":       story.StartDate.Format("2006-01-02"),
		"end_date":         story.EndDate.Format("2006-01-02"),
		"weekdays":         bitmaskToWeekdays(story.Weekdays),
		"metadata":         story.Metadata,
		"deleted_at":       story.DeletedAt,
		"created_at":       story.CreatedAt,
		"updated_at":       story.UpdatedAt,
	}

	// Add voice information if a voice is assigned
	if story.VoiceID != nil {
		response["voice"] = map[string]interface{}{
			"id":   *story.VoiceID,
			"name": story.VoiceName,
		}
	} else {
		response["voice"] = nil
	}

	return response
}

// WeekdaysInput represents weekday selection in API requests.
type WeekdaysInput struct {
	Monday    bool `json:"monday"`
	Tuesday   bool `json:"tuesday"`
	Wednesday bool `json:"wednesday"`
	Thursday  bool `json:"thursday"`
	Friday    bool `json:"friday"`
	Saturday  bool `json:"saturday"`
	Sunday    bool `json:"sunday"`
}

// ConvertToBitmask converts WeekdaysInput to a uint8 bitmask representation.
func (w WeekdaysInput) ConvertToBitmask() uint8 {
	var bitmask uint8
	if w.Monday {
		bitmask |= models.Monday
	}
	if w.Tuesday {
		bitmask |= models.Tuesday
	}
	if w.Wednesday {
		bitmask |= models.Wednesday
	}
	if w.Thursday {
		bitmask |= models.Thursday
	}
	if w.Friday {
		bitmask |= models.Friday
	}
	if w.Saturday {
		bitmask |= models.Saturday
	}
	if w.Sunday {
		bitmask |= models.Sunday
	}
	return bitmask
}

func bitmaskToWeekdays(bitmask uint8) map[string]bool {
	return map[string]bool{
		"monday":    bitmask&models.Monday != 0,
		"tuesday":   bitmask&models.Tuesday != 0,
		"wednesday": bitmask&models.Wednesday != 0,
		"thursday":  bitmask&models.Thursday != 0,
		"friday":    bitmask&models.Friday != 0,
		"saturday":  bitmask&models.Saturday != 0,
		"sunday":    bitmask&models.Sunday != 0,
	}
}

// ListStories returns a paginated list of stories with optional filters.
func (h *Handlers) ListStories(c *gin.Context) {
	limit, offset := extractPaginationParams(c)
	includeDeleted := getBoolQuery(c, "include_deleted")

	// Build query with filters
	query := `
		SELECT s.*, COALESCE(v.name, '') as voice_name
		FROM stories s 
		LEFT JOIN voices v ON s.voice_id = v.id 
		WHERE 1=1`
	countQuery := "SELECT COUNT(*) FROM stories s WHERE 1=1"
	args := []interface{}{}

	// By default, exclude deleted stories
	if !includeDeleted {
		query += " AND s.deleted_at IS NULL"
		countQuery += " AND s.deleted_at IS NULL"
	}

	// Status filter
	if status := c.Query("status"); status != "" {
		query += " AND s.status = ?"
		countQuery += " AND s.status = ?"
		args = append(args, status)
	}

	// Voice filter
	if voiceID := c.Query("voice_id"); voiceID != "" {
		query += " AND s.voice_id = ?"
		countQuery += " AND s.voice_id = ?"
		args = append(args, voiceID)
	}

	// Date filter
	if date := c.Query("date"); date != "" {
		query += " AND s.start_date <= ? AND s.end_date >= ?"
		countQuery += " AND s.start_date <= ? AND s.end_date >= ?"
		args = append(args, date, date)
	}

	// Weekday filter
	if weekday := c.Query("weekday"); weekday != "" {
		var bitmask uint8
		switch weekday {
		case "monday":
			bitmask = models.Monday
		case "tuesday":
			bitmask = models.Tuesday
		case "wednesday":
			bitmask = models.Wednesday
		case "thursday":
			bitmask = models.Thursday
		case "friday":
			bitmask = models.Friday
		case "saturday":
			bitmask = models.Saturday
		case "sunday":
			bitmask = models.Sunday
		}
		if bitmask > 0 {
			query += " AND (s.weekdays & ?) > 0"
			countQuery += " AND (s.weekdays & ?) > 0"
			args = append(args, bitmask)
		}
	}

	// Get total count
	var total int64
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := h.db.Get(&total, countQuery, countArgs...); err != nil {
		responses.InternalServerError(c, "Failed to count stories")
		return
	}

	// Add ordering and pagination
	query += " ORDER BY s.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	// Get stories
	var stories []models.Story
	if err := h.db.Select(&stories, query, args...); err != nil {
		responses.InternalServerError(c, "Failed to fetch stories")
		return
	}

	// Convert stories to response format with weekdays object
	storyResponses := make([]map[string]interface{}, len(stories))
	for i, story := range stories {
		storyResponses[i] = storyToResponse(story)
	}

	responses.Paginated(c, storyResponses, total, limit, offset)
}

// GetStory returns a single story by ID.
func (h *Handlers) GetStory(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid story ID")
		return
	}

	var story models.Story
	err = h.db.Get(&story, `
		SELECT s.*, COALESCE(v.name, '') as voice_name
		FROM stories s 
		LEFT JOIN voices v ON s.voice_id = v.id 
		WHERE s.id = ? AND s.deleted_at IS NULL`, id)
	if err == sql.ErrNoRows {
		responses.NotFound(c, "Story not found")
		return
	}
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch story")
		return
	}

	// Convert to response format
	responses.Success(c, storyToResponse(story))
}

// CreateStory creates a new story with optional audio upload.
func (h *Handlers) CreateStory(c *gin.Context) {
	// Parse multipart form
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		responses.BadRequest(c, "Failed to parse multipart form")
		return
	}

	// Get and validate required fields
	title := c.PostForm("title")
	text := c.PostForm("text")
	voiceIDStr := c.PostForm("voice_id")
	startDateStr := c.PostForm("start_date")
	endDateStr := c.PostForm("end_date")

	if title == "" || text == "" || startDateStr == "" || endDateStr == "" {
		responses.BadRequest(c, "Missing required fields: title, text, start_date, and end_date are required")
		return
	}

	// Parse optional voice_id
	var voiceID *int
	if voiceIDStr != "" {
		parsedVoiceID, err := strconv.Atoi(voiceIDStr)
		if err != nil {
			responses.BadRequest(c, "Invalid voice ID")
			return
		}
		voiceID = &parsedVoiceID
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		responses.BadRequest(c, "Invalid start date format")
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		responses.BadRequest(c, "Invalid end date format")
		return
	}

	// Get optional fields
	status := c.PostForm("status")
	if status == "" {
		status = "draft"
	}

	// Parse weekdays
	weekdaysStr := c.PostForm("weekdays")
	var weekdays WeekdaysInput
	if weekdaysStr != "" {
		if err := json.Unmarshal([]byte(weekdaysStr), &weekdays); err != nil {
			responses.BadRequest(c, "Invalid weekdays format")
			return
		}
	}
	weekdaysBitmask := weekdays.ConvertToBitmask()

	// Parse metadata
	metadata := c.PostForm("metadata")
	if metadata == "" {
		metadata = "{}"
	}

	// Create story
	result, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO stories (title, text, voice_id, status, start_date, end_date, weekdays, metadata) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		title, text, voiceID, status, startDate, endDate, weekdaysBitmask, metadata,
	)
	if err != nil {
		responses.InternalServerError(c, "Failed to create story")
		return
	}

	storyID, err := result.LastInsertId()
	if err != nil {
		responses.InternalServerError(c, "Failed to get story ID")
		return
	}

	// Handle audio upload if provided
	file, header, err := c.Request.FormFile("audio")
	if err == nil {
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error("Failed to close uploaded file: %v", err)
			}
		}()

		// Validate audio file
		if err := validation.ValidateAudioFile(header); err != nil {
			// Delete the story if validation fails
			if delErr := h.removeStoryFromDatabase(c.Request.Context(), int(storyID)); delErr != nil {
				// Log the error but continue with the main error response
				fmt.Printf("Failed to delete story after validation error: %v\n", delErr)
			}
			responses.BadRequest(c, fmt.Sprintf("Invalid audio file: %v", err))
			return
		}

		if err := h.handleAudioUpload(c, int(storyID), file, header); err != nil {
			// Delete the story if audio processing fails
			if delErr := h.removeStoryFromDatabase(c.Request.Context(), int(storyID)); delErr != nil {
				// Log the error but continue with the main error response
				fmt.Printf("Failed to delete story after processing error: %v\n", delErr)
			}
			responses.InternalServerError(c, fmt.Sprintf("Failed to process audio: %v", err))
			return
		}
	}

	// Fetch the created story
	var story models.Story
	err = h.db.Get(&story, `
		SELECT s.*, COALESCE(v.name, '') as voice_name
		FROM stories s 
		LEFT JOIN voices v ON s.voice_id = v.id 
		WHERE s.id = ?`, storyID)
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch created story")
		return
	}

	// Convert to response format
	responses.Created(c, storyToResponse(story))
}

// UpdateStory updates an existing story.
func (h *Handlers) UpdateStory(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "story")
	if !ok {
		return
	}

	// Check if story exists using DRY helper
	if !h.validateRecordExists(c, "stories", "Story", id) {
		return
	}

	// Parse multipart form
	if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
		responses.BadRequest(c, "Failed to parse multipart form")
		return
	}

	// Build update query dynamically
	updates := []string{}
	args := []interface{}{}

	if title := c.PostForm("title"); title != "" {
		updates = append(updates, "title = ?")
		args = append(args, title)
	}

	if text := c.PostForm("text"); text != "" {
		updates = append(updates, "text = ?")
		args = append(args, text)
	}

	if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
		if voiceIDStr == "null" || voiceIDStr == "" {
			// Allow setting voice_id to NULL
			updates = append(updates, "voice_id = NULL")
		} else {
			voiceID, err := strconv.Atoi(voiceIDStr)
			if err != nil {
				responses.BadRequest(c, "Invalid voice ID")
				return
			}
			updates = append(updates, "voice_id = ?")
			args = append(args, voiceID)
		}
	}

	if status := c.PostForm("status"); status != "" {
		updates = append(updates, "status = ?")
		args = append(args, status)
	}

	if startDateStr := c.PostForm("start_date"); startDateStr != "" {
		startDate, err := time.Parse("2006-01-02", startDateStr)
		if err != nil {
			responses.BadRequest(c, "Invalid start date format")
			return
		}
		updates = append(updates, "start_date = ?")
		args = append(args, startDate)
	}

	if endDateStr := c.PostForm("end_date"); endDateStr != "" {
		endDate, err := time.Parse("2006-01-02", endDateStr)
		if err != nil {
			responses.BadRequest(c, "Invalid end date format")
			return
		}
		updates = append(updates, "end_date = ?")
		args = append(args, endDate)
	}

	if weekdaysStr := c.PostForm("weekdays"); weekdaysStr != "" {
		var weekdays WeekdaysInput
		if err := json.Unmarshal([]byte(weekdaysStr), &weekdays); err != nil {
			responses.BadRequest(c, "Invalid weekdays format")
			return
		}
		updates = append(updates, "weekdays = ?")
		args = append(args, weekdays.ConvertToBitmask())
	}

	if metadata := c.PostForm("metadata"); metadata != "" {
		updates = append(updates, "metadata = ?")
		args = append(args, metadata)
	}

	// Execute update if there are fields to update
	if len(updates) > 0 {
		query := fmt.Sprintf("UPDATE stories SET %s WHERE id = ?", joinStrings(updates, ", "))
		args = append(args, id)

		if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
			responses.InternalServerError(c, "Failed to update story")
			return
		}
	}

	// Handle new audio upload if provided
	file, header, err := c.Request.FormFile("audio")
	if err == nil {
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error("Failed to close uploaded file: %v", err)
			}
		}()

		// Validate audio file
		if err := validation.ValidateAudioFile(header); err != nil {
			responses.BadRequest(c, fmt.Sprintf("Invalid audio file: %v", err))
			return
		}

		if err := h.handleAudioUpload(c, id, file, header); err != nil {
			responses.InternalServerError(c, fmt.Sprintf("Failed to process audio: %v", err))
			return
		}
	}

	// Fetch updated story
	var story models.Story
	err = h.db.Get(&story, `
		SELECT s.*, COALESCE(v.name, '') as voice_name
		FROM stories s 
		LEFT JOIN voices v ON s.voice_id = v.id 
		WHERE s.id = ?`, id)
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch updated story")
		return
	}

	// Convert to response format
	responses.Success(c, storyToResponse(story))
}

// DeleteStory soft deletes a story by setting deleted_at timestamp.
func (h *Handlers) DeleteStory(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid story ID")
		return
	}

	crud := NewCRUDHandler(h.db, "stories", WithSoftDelete("deleted_at"))
	crud.Delete(c, id)
}

// GetStoryAudio serves the audio file for a story.
func (h *Handlers) GetStoryAudio(c *gin.Context) {
	h.ServeAudio(c, AudioConfig{
		TableName:   "stories",
		IDColumn:    "id",
		FileColumn:  "audio_file",
		FilePrefix:  "story",
		ContentType: "audio/wav",
	})
}

func (h *Handlers) handleAudioUpload(c *gin.Context, storyID int, file multipart.File, header *multipart.FileHeader) error {
	// Save uploaded file temporarily with sanitized filename
	tempPath := fmt.Sprintf("/tmp/upload_%d_%s", storyID, validation.SanitizeFilename(header.Filename))

	// Create temp file and copy content
	if err := saveFile(file, tempPath); err != nil {
		return err
	}

	// Process audio with audio service
	audioPath, duration, err := h.audioSvc.ConvertStoryToWAV(c.Request.Context(), storyID, tempPath)
	if err != nil {
		return err
	}

	// Update story with audio info
	_, err = h.db.ExecContext(c.Request.Context(), "UPDATE stories SET audio_file = ?, duration_seconds = ? WHERE id = ?",
		audioPath, duration, storyID)
	return err
}

// removeStoryFromDatabase is a helper to delete a story from the database
func (h *Handlers) removeStoryFromDatabase(ctx context.Context, storyID int) error {
	_, err := h.db.ExecContext(ctx, "DELETE FROM stories WHERE id = ?", storyID)
	return err
}

// UpdateStoryState handles story soft delete and restore operations via PATCH.
func (h *Handlers) UpdateStoryState(c *gin.Context) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid story ID")
		return
	}

	var req struct {
		DeletedAt *string `json:"deleted_at"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	if req.DeletedAt == nil {
		responses.BadRequest(c, "deleted_at field is required")
		return
	}

	crud := NewCRUDHandler(h.db, "stories", WithSoftDelete("deleted_at"))

	// null or empty string = restore, any other value = soft delete
	if *req.DeletedAt == "" || *req.DeletedAt == "null" {
		crud.Restore(c, id)
	} else {
		crud.SoftDelete(c, id)
	}
}
