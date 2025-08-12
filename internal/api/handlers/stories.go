package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
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
	Weekdays        uint8           `json:"-" db:"weekdays"`
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

// bitmaskToWeekdays converts weekday bitmask to map
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

// ListStories returns a paginated list of stories
func (h *Handlers) ListStories(c *gin.Context) {
	limit, offset := utils.GetPagination(c)

	// Build query with optional filters
	query := utils.BuildStoryQuery("", c.Query("include_deleted") == "true")
	countQuery := "SELECT COUNT(*) FROM stories s"
	args := []interface{}{}

	// Add deleted filter to count query
	if c.Query("include_deleted") != "true" {
		countQuery += " WHERE s.deleted_at IS NULL"
	}

	// Add filters
	if status := c.Query("status"); status != "" {
		if c.Query("include_deleted") != "true" {
			query += " AND s.status = ?"
			countQuery += " AND s.status = ?"
		} else {
			query += " AND s.status = ?"
			countQuery += " WHERE s.status = ?"
		}
		args = append(args, status)
	}

	if voiceID := c.Query("voice_id"); voiceID != "" {
		if len(args) > 0 {
			query += " AND s.voice_id = ?"
			countQuery += " AND s.voice_id = ?"
		} else {
			query += " AND s.voice_id = ?"
			if c.Query("include_deleted") == "true" {
				countQuery += " WHERE s.voice_id = ?"
			} else {
				countQuery += " AND s.voice_id = ?"
			}
		}
		args = append(args, voiceID)
	}

	// Get total count
	total, err := utils.CountWithJoins(h.db, countQuery, args...)
	if err != nil {
		utils.InternalServerError(c, "Failed to count stories")
		return
	}

	// Get paginated data
	query += " ORDER BY s.id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	var stories []StoryResponse
	if err := h.db.Select(&stories, query, args...); err != nil {
		utils.InternalServerError(c, "Failed to fetch stories")
		return
	}

	// Add audio URLs and weekdays map
	for i := range stories {
		hasAudio := stories[i].AudioFile != ""
		stories[i].AudioURL = GetStoryAudioURL(stories[i].ID, hasAudio)
		stories[i].WeekdaysMap = bitmaskToWeekdays(stories[i].Weekdays)
	}

	utils.PaginatedResponse(c, stories, total, limit, offset)
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
			utils.NotFound(c, "Story")
		} else {
			utils.InternalServerError(c, "Failed to fetch story")
		}
		return
	}

	// Add audio URL and weekdays map
	hasAudio := story.AudioFile != ""
	story.AudioURL = GetStoryAudioURL(story.ID, hasAudio)
	story.WeekdaysMap = bitmaskToWeekdays(story.Weekdays)

	utils.Success(c, story)
}

// CreateStory creates a new story with optional audio upload
func (h *Handlers) CreateStory(c *gin.Context) {
	// Parse form data
	title := c.PostForm("title")
	if title == "" {
		utils.BadRequest(c, "Title is required")
		return
	}

	text := c.PostForm("text")
	if text == "" {
		utils.BadRequest(c, "Text is required")
		return
	}

	status := c.PostForm("status")
	if status == "" {
		status = "draft"
	}
	if status != "draft" && status != "active" && status != "expired" {
		utils.BadRequest(c, "Status must be one of: draft, active, expired")
		return
	}

	// Parse voice ID (optional)
	var voiceID *int
	if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
		id, err := strconv.Atoi(voiceIDStr)
		if err != nil || id <= 0 {
			utils.BadRequest(c, "Valid voice_id is required")
			return
		}
		if !utils.ValidateResourceExists(c, h.db, "voices", "Voice", id) {
			return
		}
		voiceID = &id
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

	// Parse weekdays
	var weekdaysBitmask uint8
	if weekdaysStr := c.PostForm("weekdays"); weekdaysStr != "" {
		var weekdaysMap map[string]bool
		if err := json.Unmarshal([]byte(weekdaysStr), &weekdaysMap); err != nil {
			utils.BadRequest(c, "Invalid weekdays format - must be valid JSON")
			return
		}

		for day, enabled := range weekdaysMap {
			if enabled {
				weekdaysBitmask |= utils.WeekdayStringToBitmask(day)
			}
		}
	}

	metadata := c.PostForm("metadata")
	// Handle empty metadata - MySQL JSON column requires NULL not empty string
	var metadataValue interface{}
	if metadata == "" {
		metadataValue = nil
	} else {
		metadataValue = metadata
	}

	// Create story
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stories (title, text, voice_id, status, start_date, end_date, weekdays, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		title, text, voiceID, status, startDate, endDate, weekdaysBitmask, metadataValue)
	if err != nil {
		logger.Error("Database error creating story: %v", err)
		utils.InternalServerError(c, "Failed to create story")
		return
	}

	storyID, _ := result.LastInsertId()

	// Handle optional audio file upload
	_, _, err = c.Request.FormFile("audio")
	if err == nil {
		tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", storyID))
		if err != nil {
			utils.BadRequest(c, err.Error())
			return
		}
		defer cleanup()

		// Process audio with audio service
		if _, _, err := h.audioSvc.ConvertStoryToWAV(c.Request.Context(), int(storyID), tempPath); err != nil {
			logger.Error("Failed to process story audio: %v", err)
			utils.InternalServerError(c, "Failed to process audio")
			return
		}

		// Update database with relative audio path
		relativePath := utils.GetStoryRelativePath(h.config, int(storyID))
		_, err = h.db.ExecContext(c.Request.Context(),
			"UPDATE stories SET audio_file = ? WHERE id = ?", relativePath, storyID)
		if err != nil {
			utils.InternalServerError(c, "Failed to update audio reference")
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

	if title := c.PostForm("title"); title != "" {
		updates = append(updates, "title = ?")
		args = append(args, title)
	}

	if text := c.PostForm("text"); text != "" {
		updates = append(updates, "text = ?")
		args = append(args, text)
	}

	if status := c.PostForm("status"); status != "" {
		if status != "draft" && status != "active" && status != "expired" {
			utils.BadRequest(c, "Status must be one of: draft, active, expired")
			return
		}
		updates = append(updates, "status = ?")
		args = append(args, status)
	}

	if voiceIDStr := c.PostForm("voice_id"); voiceIDStr != "" {
		voiceID, err := strconv.Atoi(voiceIDStr)
		if err != nil || voiceID <= 0 {
			utils.BadRequest(c, "Valid voice_id is required")
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

	if weekdaysStr := c.PostForm("weekdays"); weekdaysStr != "" {
		var weekdaysMap map[string]bool
		if err := json.Unmarshal([]byte(weekdaysStr), &weekdaysMap); err != nil {
			utils.BadRequest(c, "Invalid weekdays format - must be valid JSON")
			return
		}

		var weekdaysBitmask uint8
		for day, enabled := range weekdaysMap {
			if enabled {
				weekdaysBitmask |= utils.WeekdayStringToBitmask(day)
			}
		}
		updates = append(updates, "weekdays = ?")
		args = append(args, weekdaysBitmask)
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

	if len(updates) == 0 {
		utils.BadRequest(c, "No fields to update")
		return
	}

	// Execute update
	query := "UPDATE stories SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
		utils.InternalServerError(c, "Failed to update story")
		return
	}

	utils.SuccessWithMessage(c, "Story updated successfully")
}
