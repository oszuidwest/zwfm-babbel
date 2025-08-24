// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// GetBulletinAudioURL returns the API URL for downloading a bulletin's audio file.
func GetBulletinAudioURL(bulletinID int) string {
	return fmt.Sprintf("/bulletins/%d/audio", bulletinID)
}

// BulletinRequest represents the request parameters for bulletin generation.
type BulletinRequest struct {
	StationID int    `json:"station_id" binding:"required"`
	Date      string `json:"date"`
}

// BulletinResponse represents the API response for bulletin generation.
type BulletinResponse struct {
	AudioURL string         `json:"audio_url"`
	Duration float64        `json:"duration"`
	Stories  []models.Story `json:"stories"`
	Station  models.Station `json:"station"`
}

// BulletinInfo contains metadata about a generated bulletin.
type BulletinInfo struct {
	ID           int64
	Station      models.Station
	Stories      []models.Story
	BulletinPath string
	Duration     float64
	FileSize     int64
	CreatedAt    time.Time
}

// createBulletin handles the complete bulletin creation process
func (h *Handlers) createBulletin(c *gin.Context, req BulletinRequest) (*BulletinInfo, error) {
	// Parse date or use today
	targetDate, err := parseTargetDate(req.Date)
	if err != nil {
		return nil, fmt.Errorf("invalid date format")
	}

	// Get station
	var station models.Station
	err = h.db.Get(&station, "SELECT * FROM stations WHERE id = ?", req.StationID)
	if err != nil {
		return nil, fmt.Errorf("station not found")
	}

	// Get stories for the date
	weekdayColumn := getWeekdayColumn(targetDate.Weekday())

	var stories []models.Story
	query := fmt.Sprintf(`
		SELECT s.*, v.name as voice_name, sv.jingle_file as voice_jingle, sv.mix_point as voice_mix_point
		FROM stories s 
		JOIN voices v ON s.voice_id = v.id 
		JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = s.voice_id
		WHERE s.deleted_at IS NULL 
		AND s.audio_file IS NOT NULL 
		AND s.audio_file != ''
		AND s.start_date <= ? 
		AND s.end_date >= ?
		AND s.%s = 1
		ORDER BY RAND()
		LIMIT ?`, weekdayColumn)

	err = h.db.Select(&stories, query, req.StationID, targetDate, targetDate, station.MaxStoriesPerBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stories: %w", err)
	}

	if len(stories) == 0 {
		return nil, fmt.Errorf("no stories available")
	}

	// Generate consistent paths using single timestamp
	timestamp := time.Now()
	bulletinPath, relativePath := utils.GenerateBulletinPaths(h.config, req.StationID, timestamp)

	// Create bulletin using the generated absolute path
	createdPath, err := h.audioSvc.CreateBulletin(c.Request.Context(), &station, stories, bulletinPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create bulletin: %w", err)
	}

	// Verify the paths match (should always be true with unified function)
	if createdPath != bulletinPath {
		fmt.Printf("WARNING: Path mismatch - expected %s, got %s\n", bulletinPath, createdPath)
	}

	// Get file info (bulletinPath is the full absolute path)
	fileInfo, err := os.Stat(bulletinPath)
	var fileSize int64
	if err == nil {
		fileSize = fileInfo.Size()
	} else {
		fmt.Printf("WARNING: Failed to get file size for %s: %v\n", bulletinPath, err)
	}

	// Calculate total duration including mix point and pauses
	var totalDuration float64

	// Calculate total duration of all stories + pauses
	var storiesDuration float64
	for _, story := range stories {
		if story.DurationSeconds != nil {
			storiesDuration += *story.DurationSeconds
		}
	}
	if station.PauseSeconds > 0 && len(stories) > 1 {
		storiesDuration += station.PauseSeconds * float64(len(stories)-1)
	}

	// Add mix point delay (when voice starts over jingle)
	var mixPointDelay float64
	if len(stories) > 0 && stories[0].VoiceMixPoint > 0 {
		mixPointDelay = stories[0].VoiceMixPoint
	}

	// Total duration = stories duration + pauses + mix point delay
	// The bulletin ends when all stories finish playing (jingle plays underneath)
	totalDuration = storiesDuration + mixPointDelay

	// Save bulletin record to database using the consistent relative path

	result, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO bulletins (station_id, filename, file_path, duration_seconds, file_size, story_count)
		VALUES (?, ?, ?, ?, ?, ?)`,
		req.StationID,
		filepath.Base(bulletinPath),
		relativePath,
		totalDuration,
		fileSize,
		len(stories),
	)

	var bulletinID int64
	if err == nil {
		var idErr error
		bulletinID, idErr = result.LastInsertId()
		if idErr != nil {
			fmt.Printf("WARNING: Failed to get bulletin ID: %v\n", idErr)
		}

		// Insert bulletin-story relationships with order
		if bulletinID > 0 {
			for i, story := range stories {
				_, err = h.db.ExecContext(c.Request.Context(),
					"INSERT INTO bulletin_stories (bulletin_id, story_id, story_order) VALUES (?, ?, ?)",
					bulletinID, story.ID, i,
				)
				if err != nil {
					fmt.Printf("WARNING: Failed to save bulletin-story relationship: %v\n", err)
				}
			}
		}
	} else {
		fmt.Printf("WARNING: Failed to save bulletin record to database: %v\n", err)
	}

	return &BulletinInfo{
		ID:           bulletinID,
		Station:      station,
		Stories:      stories,
		BulletinPath: bulletinPath,
		Duration:     totalDuration,
		FileSize:     fileSize,
		CreatedAt:    time.Now(),
	}, nil
}

// GenerateBulletin generates a news bulletin for a station.
func (h *Handlers) GenerateBulletin(c *gin.Context) {
	stationID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var req struct {
		Date string `json:"date"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "request_body",
			Message: "Invalid request body",
		}})
		return
	}

	// Create BulletinRequest with station ID from URL
	bulletinReq := BulletinRequest{
		StationID: stationID,
		Date:      req.Date,
	}

	// Parse query parameters using helper functions
	includeStoryList := c.Query("include_story_list") == "true"
	forceNew := c.Query("force") == "true"
	download := c.Query("download") == "true"
	maxAgeStr := c.Query("max_age")

	// Check if we should return existing bulletin
	if !forceNew && maxAgeStr != "" {
		maxAge, err := time.ParseDuration(maxAgeStr + "s")
		if err == nil && maxAge > 0 {
			// Check for recent bulletin using helper function
			existingBulletin, err := h.getLatestBulletin(bulletinReq.StationID, &maxAge)
			if err == nil {
				// Handle download if requested
				if download {
					c.Header("Content-Description", "File Transfer")
					c.Header("Content-Transfer-Encoding", "binary")
					c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", existingBulletin.Filename))
					c.Header("Content-Type", "audio/wav")
					c.Header("X-Bulletin-Cached", "true")
					c.File(existingBulletin.FilePath)
					return
				}

				// Return existing bulletin metadata
				response := h.bulletinToResponse(existingBulletin)
				response["cached"] = true

				// Fetch stories if requested
				if includeStoryList {
					stories, err := h.getStoriesForBulletin(existingBulletin)
					if err == nil && len(stories) > 0 {
						response["stories"] = stories
					}
				}

				utils.Success(c, response)
				return
			}
		}
	}

	// Generate new bulletin
	bulletinInfo, err := h.createBulletin(c, bulletinReq)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "station not found"):
			utils.ProblemNotFound(c, "Station")
		case strings.Contains(err.Error(), "no stories available"):
			utils.ProblemNotFound(c, "No stories available for the specified date")
		case strings.Contains(err.Error(), "invalid date format"):
			utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
				Field:   "date",
				Message: "Invalid date format",
			}})
		default:
			fmt.Printf("ERROR: Failed to generate bulletin: %v\n", err)
			utils.ProblemInternalServer(c, "Failed to generate bulletin")
		}
		return
	}

	// Handle download if requested
	if download {
		c.Header("Content-Description", "File Transfer")
		c.Header("Content-Transfer-Encoding", "binary")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(bulletinInfo.BulletinPath)))
		c.Header("Content-Type", "audio/wav")
		c.Header("X-Bulletin-Cached", "false")
		c.Header("X-Bulletin-Duration", fmt.Sprintf("%.2f", bulletinInfo.Duration))
		c.Header("X-Bulletin-Stories", fmt.Sprintf("%d", len(bulletinInfo.Stories)))
		c.File(bulletinInfo.BulletinPath)
		return
	}

	// Build response based on include_story_list parameter
	response := h.bulletinInfoToResponse(bulletinInfo, includeStoryList)
	response["cached"] = false
	utils.Success(c, response)
}



// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if bulletin exists first
	if !utils.ValidateResourceExists(c, h.db, "bulletins", "Bulletin", bulletinID) {
		return
	}

	// Configure modern query with field mappings, search fields, and bulletin_id filter
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT bs.id, bs.bulletin_id, bs.story_id, bs.story_order, 
			            bs.created_at, b.station_id, s.name as station_name, 
			            st.title as story_title, b.filename as bulletin_filename
			            FROM bulletin_stories bs
			            JOIN bulletins b ON bs.bulletin_id = b.id
			            JOIN stations s ON b.station_id = s.id
			            JOIN stories st ON bs.story_id = st.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletin_stories bs JOIN bulletins b ON bs.bulletin_id = b.id JOIN stations s ON b.station_id = s.id JOIN stories st ON bs.story_id = st.id",
			DefaultOrder: "bs.story_order ASC",
			Filters: []utils.FilterConfig{
				{
					Column: "bulletin_id",
					Table:  "bs",
					Value:  bulletinID,
				},
			},
			PostProcessor: func(result interface{}) {
				bulletinStories := result.(*[]models.BulletinStory)
				// Convert to the expected nested response format
				processedResults := make([]map[string]interface{}, len(*bulletinStories))
				for i, bs := range *bulletinStories {
					processedResults[i] = map[string]interface{}{
						"id":          bs.ID,
						"bulletin_id": bs.BulletinID,
						"story_id":    bs.StoryID,
						"story_order": bs.StoryOrder,
						"created_at":  bs.CreatedAt,
						"station": map[string]interface{}{
							"id":   bs.StationID,
							"name": bs.StationName,
						},
						"story": map[string]interface{}{
							"id":    bs.StoryID,
							"title": bs.StoryTitle,
						},
						"bulletin": map[string]interface{}{
							"id":       bs.BulletinID,
							"filename": bs.BulletinFilename,
						},
					}
				}
				// Replace the slice content with the processed format
				*bulletinStories = (*bulletinStories)[:0] // Clear the slice but keep capacity
				// Use interface{} to store the processed results in the context
				c.Set("processed_results", processedResults)
			},
		},
		SearchFields:      []string{"st.title", "s.name"},
		TableAlias:        "bs",
		DefaultFields:     "bs.id, bs.bulletin_id, bs.story_id, bs.story_order, bs.created_at, b.station_id, s.name as station_name, st.title as story_title, b.filename as bulletin_filename",
		DisableSoftDelete: true, // bulletin_stories table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":                "bs.id",
			"bulletin_id":       "bs.bulletin_id",
			"story_id":          "bs.story_id",
			"story_order":       "bs.story_order",
			"created_at":        "bs.created_at",
			"station_id":        "b.station_id",
			"station_name":      "s.name",
			"story_title":       "st.title",
			"bulletin_filename": "b.filename",
		},
	}

	var bulletinStories []models.BulletinStory
	utils.ModernListWithQuery(c, h.db, config, &bulletinStories)

	// Check if ModernListWithQuery already handled the response (error case)
	if c.IsAborted() {
		return
	}

	// Check if we have processed results from PostProcessor
	if processedResults, exists := c.Get("processed_results"); exists {
		// Get pagination data
		responseData := c.Keys["pagination_data"]
		paginationInfo, ok := responseData.(map[string]interface{})
		if !ok {
			utils.ProblemInternalServer(c, "Failed to get pagination data")
			return
		}
		
		// Send the processed nested response
		utils.PaginatedResponse(c, processedResults, 
			paginationInfo["total"].(int64), 
			paginationInfo["limit"].(int), 
			paginationInfo["offset"].(int))
		return
	}

	// Fallback if PostProcessor didn't run (shouldn't happen)
	utils.ProblemInternalServer(c, "Failed to process bulletin stories")
}

// bulletinToResponse creates a consistent response format for bulletin endpoints
func (h *Handlers) bulletinToResponse(bulletin *models.Bulletin) map[string]interface{} {
	bulletinURL := GetBulletinAudioURL(bulletin.ID)

	response := map[string]interface{}{
		"station_id":   bulletin.StationID,
		"station_name": bulletin.StationName,
		"audio_url":    bulletinURL,
		"filename":     bulletin.Filename,
		"created_at":   bulletin.CreatedAt,
		"duration":     bulletin.DurationSeconds,
		"file_size":    bulletin.FileSize,
		"story_count":  bulletin.StoryCount,
	}

	if bulletin.ID > 0 {
		response["id"] = bulletin.ID
	}

	return response
}

// bulletinInfoToResponse creates response from BulletinInfo
func (h *Handlers) bulletinInfoToResponse(info *BulletinInfo, includeStoryList bool) map[string]interface{} {
	bulletinURL := GetBulletinAudioURL(int(info.ID))

	response := map[string]interface{}{
		"station_id":   info.Station.ID,
		"station_name": info.Station.Name,
		"audio_url":    bulletinURL,
		"filename":     filepath.Base(info.BulletinPath),
		"created_at":   info.CreatedAt,
		"duration":     info.Duration,
		"file_size":    info.FileSize,
		"story_count":  len(info.Stories),
	}

	if info.ID > 0 {
		response["id"] = info.ID
	}

	if includeStoryList && len(info.Stories) > 0 {
		response["stories"] = info.Stories
	}

	return response
}

// GetStationBulletins returns bulletins for a specific station with pagination and filtering
func (h *Handlers) GetStationBulletins(c *gin.Context) {
	stationID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if station exists first
	if !utils.ValidateResourceExists(c, h.db, "stations", "Station", stationID) {
		return
	}

	// Check for 'latest' query parameter for RESTful latest bulletin access
	if c.Query("latest") == "true" || c.Query("limit") == "1" {
		bulletin, err := h.getLatestBulletin(stationID, nil)
		if err != nil {
			utils.ProblemNotFound(c, "No bulletin found for this station")
			return
		}
		response := h.bulletinToResponse(bulletin)
		utils.Success(c, response)
		return
	}

	// Parse include_stories parameter
	includeStories := c.Query("include_stories") == "true"

	// Configure modern query with field mappings, search fields, and station_id filter
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT b.id, b.station_id, b.filename, b.file_path, b.duration_seconds, 
			            b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name
			            FROM bulletins b 
			            JOIN stations s ON b.station_id = s.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletins b JOIN stations s ON b.station_id = s.id",
			DefaultOrder: "b.created_at DESC",
			Filters: []utils.FilterConfig{
				{
					Column: "station_id",
					Table:  "b",
					Value:  stationID,
				},
			},
		},
		SearchFields:      []string{"b.filename", "s.name"},
		TableAlias:        "b",
		DefaultFields:     "b.id, b.station_id, b.filename, b.file_path, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name",
		DisableSoftDelete: true, // Bulletins table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":               "b.id",
			"station_id":       "b.station_id",
			"filename":         "b.filename",
			"file_path":        "b.file_path",
			"duration_seconds": "b.duration_seconds",
			"duration":         "b.duration_seconds", // Allow both field names
			"file_size":        "b.file_size",
			"story_count":      "b.story_count",
			"metadata":         "b.metadata",
			"created_at":       "b.created_at",
			"station_name":     "s.name",
		},
	}

	var bulletins []models.Bulletin
	utils.ModernListWithQuery(c, h.db, config, &bulletins)

	// Check if ModernListWithQuery already handled the response (error case)
	if c.IsAborted() {
		return
	}

	// Get the response data to extract total count
	responseData := c.Keys["pagination_data"]
	paginationInfo, ok := responseData.(map[string]interface{})
	if !ok {
		// ModernListWithQuery didn't set pagination data, which means it already sent response
		return
	}

	// Convert to response format
	bulletinResponses := make([]map[string]interface{}, len(bulletins))
	for i, bulletin := range bulletins {
		response := h.bulletinToResponse(&bulletin)

		// Add stories if requested
		if includeStories {
			stories, err := h.getStoriesForBulletin(&bulletin)
			if err == nil && len(stories) > 0 {
				response["stories"] = stories
			}
		}

		bulletinResponses[i] = response
	}

	// Send the custom formatted response with pagination metadata
	total := paginationInfo["total"].(int)
	limit := paginationInfo["limit"].(int)
	offset := paginationInfo["offset"].(int)
	utils.PaginatedResponse(c, bulletinResponses, int64(total), limit, offset)
}

// BulletinListResponse represents the response format for bulletins in list view with computed fields.
type BulletinListResponse struct {
	models.Bulletin
	AudioURL string         `json:"audio_url,omitempty"`
	Stories  []models.Story `json:"stories,omitempty"`
}

// ListBulletins returns a paginated list of bulletins with modern query parameter support
func (h *Handlers) ListBulletins(c *gin.Context) {
	// Parse include_stories parameter
	includeStories := c.Query("include_stories") == "true"

	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT b.id, b.station_id, b.filename, b.file_path, b.duration_seconds, 
			            b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name
			            FROM bulletins b 
			            JOIN stations s ON b.station_id = s.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletins b JOIN stations s ON b.station_id = s.id",
			DefaultOrder: "b.created_at DESC",
		},
		SearchFields:      []string{"b.filename", "s.name"},
		TableAlias:        "b",
		DefaultFields:     "b.id, b.station_id, b.filename, b.file_path, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name",
		DisableSoftDelete: true, // Bulletins table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":               "b.id",
			"station_id":       "b.station_id",
			"filename":         "b.filename",
			"file_path":        "b.file_path",
			"duration_seconds": "b.duration_seconds",
			"duration":         "b.duration_seconds", // Allow both field names
			"file_size":        "b.file_size",
			"story_count":      "b.story_count",
			"metadata":         "b.metadata",
			"created_at":       "b.created_at",
			"station_name":     "s.name",
		},
	}

	var bulletins []models.Bulletin
	utils.ModernListWithQuery(c, h.db, config, &bulletins)

	// Check if ModernListWithQuery already handled the response (error case)
	if c.IsAborted() {
		return
	}

	// Get the response data to extract total count
	responseData := c.Keys["pagination_data"]
	paginationInfo, ok := responseData.(map[string]interface{})
	if !ok {
		// ModernListWithQuery didn't set pagination data, which means it already sent response
		return
	}

	// Convert to response format
	bulletinResponses := make([]map[string]interface{}, len(bulletins))
	for i, bulletin := range bulletins {
		response := h.bulletinToResponse(&bulletin)

		// Add stories if requested
		if includeStories {
			stories, err := h.getStoriesForBulletin(&bulletin)
			if err == nil && len(stories) > 0 {
				response["stories"] = stories
			}
		}

		bulletinResponses[i] = response
	}

	// Send the custom formatted response with pagination metadata
	total := paginationInfo["total"].(int)
	limit := paginationInfo["limit"].(int)
	offset := paginationInfo["offset"].(int)
	utils.PaginatedResponse(c, bulletinResponses, int64(total), limit, offset)
}

// getStoriesForBulletin retrieves the stories that were used in a bulletin
func (h *Handlers) getStoriesForBulletin(bulletin *models.Bulletin) ([]models.Story, error) {
	var stories []models.Story

	// Get stories from junction table, ordered by story_order
	err := h.db.Select(&stories, `
		SELECT s.*, v.name as voice_name
		FROM bulletin_stories bs
		JOIN stories s ON bs.story_id = s.id
		JOIN voices v ON s.voice_id = v.id
		WHERE bs.bulletin_id = ?
		ORDER BY bs.story_order`,
		bulletin.ID,
	)

	return stories, err
}

// GetStoryBulletinHistory returns all bulletins that included a specific story.
func (h *Handlers) GetStoryBulletinHistory(c *gin.Context) {
	storyID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Verify story exists
	var story models.Story
	err := h.db.Get(&story, "SELECT * FROM stories WHERE id = ?", storyID)
	if err != nil {
		utils.ProblemNotFound(c, "Story")
		return
	}

	// Get bulletin history for this story
	var results []struct {
		models.Bulletin
		StoryOrder int       `db:"story_order"`
		IncludedAt time.Time `db:"included_at"`
	}

	err = h.db.Select(&results, `
		SELECT b.*, s.name as station_name, bs.story_order, bs.created_at as included_at
		FROM bulletin_stories bs
		JOIN bulletins b ON bs.bulletin_id = b.id
		JOIN stations s ON b.station_id = s.id
		WHERE bs.story_id = ?
		ORDER BY bs.created_at DESC`,
		storyID,
	)

	if err != nil {
		utils.ProblemInternalServer(c, "Failed to fetch bulletin history")
		return
	}

	// Convert to response format
	bulletinHistory := make([]map[string]interface{}, len(results))
	for i, result := range results {
		response := h.bulletinToResponse(&result.Bulletin)
		response["story_order"] = result.StoryOrder
		response["included_at"] = result.IncludedAt
		bulletinHistory[i] = response
	}

	utils.Success(c, map[string]interface{}{
		"story_id":    story.ID,
		"story_title": story.Title,
		"bulletins":   bulletinHistory,
		"total":       len(bulletinHistory),
	})
}

// parseTargetDate parses date string or returns current date
func parseTargetDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Now(), nil
	}
	return time.Parse("2006-01-02", dateStr)
}

// getWeekdayColumn returns the corresponding weekday column name for a time.Weekday
func getWeekdayColumn(weekday time.Weekday) string {
	switch weekday {
	case time.Monday:
		return "monday"
	case time.Tuesday:
		return "tuesday"
	case time.Wednesday:
		return "wednesday"
	case time.Thursday:
		return "thursday"
	case time.Friday:
		return "friday"
	case time.Saturday:
		return "saturday"
	case time.Sunday:
		return "sunday"
	default:
		return "monday" // fallback
	}
}

// getLatestBulletin is a helper function to fetch the latest bulletin for a station
// This centralizes the query logic that's used in multiple places
// If maxAge is provided, only returns bulletins newer than that duration
func (h *Handlers) getLatestBulletin(stationID int, maxAge *time.Duration) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	// Build query with optional age filter
	query := `
		SELECT b.*, s.name as station_name 
		FROM bulletins b
		JOIN stations s ON b.station_id = s.id
		WHERE b.station_id = ?`

	args := []interface{}{stationID}

	// Add age filter if specified
	if maxAge != nil {
		query += ` AND b.created_at >= ?`
		args = append(args, time.Now().Add(-*maxAge))
	}

	query += ` ORDER BY b.created_at DESC LIMIT 1`

	err := h.db.Get(&bulletin, query, args...)
	if err != nil {
		return nil, err
	}

	return &bulletin, nil
}

// GetBulletinAudio serves the audio file for a specific bulletin.
func (h *Handlers) GetBulletinAudio(c *gin.Context) {
	h.ServeAudio(c, AudioConfig{
		TableName:   "bulletins",
		IDColumn:    "id",
		FileColumn:  "file_path",
		FilePrefix:  "bulletin",
		ContentType: "audio/wav",
	})
}
