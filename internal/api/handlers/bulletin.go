package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// GetBulletinAudioURL returns the API URL for downloading a bulletin's audio file.
func GetBulletinAudioURL(bulletinID int) *string {
	if bulletinID <= 0 {
		return nil
	}
	url := fmt.Sprintf("/api/v1/bulletins/%d/audio", bulletinID)
	return &url
}

// BulletinRequest represents the request parameters for bulletin generation.
type BulletinRequest struct {
	StationID int    `json:"station_id" binding:"required"`
	Date      string `json:"date"`
}

// BulletinResponse represents the API response for bulletin generation.
type BulletinResponse struct {
	AudioURL *string        `json:"audio_url"`
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
	weekday := dateToWeekdayBitmask(targetDate)

	var stories []models.Story
	err = h.db.Select(&stories, `
		SELECT s.*, v.name as voice_name, sv.jingle_file as voice_jingle, sv.mix_point as voice_mix_point FROM (
			SELECT s.id, COALESCE(MAX(b.created_at), '1970-01-01 00:00:00') as last_used
			FROM stories s 
			LEFT JOIN bulletin_stories bs ON bs.story_id = s.id
			LEFT JOIN bulletins b ON b.id = bs.bulletin_id AND b.station_id = ?
			WHERE s.deleted_at IS NULL 
			AND s.audio_file IS NOT NULL 
			AND s.audio_file != ''
			AND s.start_date <= ? 
			AND s.end_date >= ?
			AND (s.weekdays & ?) > 0
			AND EXISTS (
				SELECT 1 FROM station_voices sv2 
				WHERE sv2.station_id = ? AND sv2.voice_id = s.voice_id
			)
			GROUP BY s.id
			ORDER BY last_used ASC
			LIMIT ?
		) AS selected
		JOIN stories s ON s.id = selected.id
		JOIN voices v ON s.voice_id = v.id 
		JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = s.voice_id
		ORDER BY RAND()`,
		req.StationID, targetDate, targetDate, weekday, req.StationID, station.MaxStoriesPerBlock, req.StationID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stories: %w", err)
	}

	if len(stories) == 0 {
		return nil, fmt.Errorf("no stories available")
	}

	// Create bulletin (using existing audio service with station and stories)
	bulletinPath, err := h.audioSvc.CreateBulletin(c.Request.Context(), &station, stories)
	if err != nil {
		return nil, fmt.Errorf("failed to create bulletin: %w", err)
	}

	// Get file info (bulletinPath is already the full absolute path)
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

	// Save bulletin record to database
	result, err := h.db.ExecContext(c.Request.Context(), `
		INSERT INTO bulletins (station_id, filename, file_path, duration_seconds, file_size, story_count)
		VALUES (?, ?, ?, ?, ?, ?)`,
		req.StationID,
		filepath.Base(bulletinPath),
		bulletinPath,
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
	stationID, ok := validateAndGetIDParam(c, "station")
	if !ok {
		return
	}

	var req struct {
		Date string `json:"date"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Create BulletinRequest with station ID from URL
	bulletinReq := BulletinRequest{
		StationID: stationID,
		Date:      req.Date,
	}

	// Parse query parameters using helper functions
	includeStoryList := getBoolQuery(c, "include_story_list")
	forceNew := getBoolQuery(c, "force")
	download := getBoolQuery(c, "download")
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

				responses.Success(c, response)
				return
			}
		}
	}

	// Generate new bulletin
	bulletinInfo, err := h.createBulletin(c, bulletinReq)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "station not found"):
			responses.NotFound(c, "Station not found")
		case strings.Contains(err.Error(), "no stories available"):
			responses.NotFound(c, "No stories available for the specified date")
		case strings.Contains(err.Error(), "invalid date format"):
			responses.BadRequest(c, "Invalid date format")
		default:
			fmt.Printf("ERROR: Failed to generate bulletin: %v\n", err)
			responses.InternalServerError(c, "Failed to generate bulletin")
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
	responses.Success(c, response)
}

// BulletinStoryQueryConfig encapsulates query parameters for bulletin-story relationships.
type BulletinStoryQueryConfig struct {
	WhereClause string
	OrderClause string
	Args        []interface{}
}

func (h *Handlers) getBulletinStoryRelationships(c *gin.Context, config BulletinStoryQueryConfig, limit, offset int) ([]map[string]interface{}, int64, error) {
	// Base query with joins
	baseQuery := `
		SELECT bs.id, bs.bulletin_id, bs.story_id, bs.story_order, 
		       bs.created_at,
		       b.station_id, s.name as station_name, 
		       st.title as story_title, b.filename as bulletin_filename
		FROM bulletin_stories bs
		JOIN bulletins b ON bs.bulletin_id = b.id
		JOIN stations s ON b.station_id = s.id
		JOIN stories st ON bs.story_id = st.id`

	// Build full query
	query := baseQuery + " WHERE " + config.WhereClause + " " + config.OrderClause + " LIMIT ? OFFSET ?"
	countQuery := "SELECT COUNT(*) FROM bulletin_stories bs JOIN bulletins b ON bs.bulletin_id = b.id WHERE " + config.WhereClause

	// Get total count
	var total int64
	countArgs := make([]interface{}, len(config.Args))
	copy(countArgs, config.Args)
	if err := h.db.Get(&total, countQuery, countArgs...); err != nil {
		return nil, 0, err
	}

	// Execute main query
	queryArgs := make([]interface{}, len(config.Args)+2)
	copy(queryArgs, config.Args)
	queryArgs[len(config.Args)] = limit
	queryArgs[len(config.Args)+1] = offset
	rows, err := h.db.QueryContext(c.Request.Context(), query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			fmt.Printf("WARNING: Failed to close rows: %v\n", closeErr)
		}
	}()

	var results []map[string]interface{}
	for rows.Next() {
		var id, bulletinID, storyID, storyOrder, stationID int
		var createdAt time.Time
		var stationName, storyTitle, bulletinFilename string

		if err := rows.Scan(&id, &bulletinID, &storyID, &storyOrder, &createdAt, &stationID, &stationName, &storyTitle, &bulletinFilename); err != nil {
			return nil, 0, err
		}

		result := map[string]interface{}{
			"id":          id,
			"bulletin_id": bulletinID,
			"story_id":    storyID,
			"story_order": storyOrder,
			"created_at":  createdAt,
			"station": map[string]interface{}{
				"id":   stationID,
				"name": stationName,
			},
			"story": map[string]interface{}{
				"id":    storyID,
				"title": storyTitle,
			},
			"bulletin": map[string]interface{}{
				"id":       bulletinID,
				"filename": bulletinFilename,
			},
		}
		results = append(results, result)
	}

	return results, total, nil
}

// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := validateAndGetIDParam(c, "bulletin")
	if !ok {
		return
	}

	// Check if bulletin exists first (using existing helper)
	if !h.validateRecordExists(c, "bulletins", "Bulletin", bulletinID) {
		return
	}

	limit, offset := extractPaginationParams(c)

	config := BulletinStoryQueryConfig{
		WhereClause: "bs.bulletin_id = ?",
		OrderClause: "ORDER BY bs.story_order ASC",
		Args:        []interface{}{bulletinID},
	}

	stories, total, err := h.getBulletinStoryRelationships(c, config, limit, offset)
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch bulletin stories")
		return
	}

	responses.Paginated(c, stories, total, limit, offset)
}

// bulletinToResponse creates a consistent response format for bulletin endpoints
func (h *Handlers) bulletinToResponse(bulletin *models.Bulletin) map[string]interface{} {
	audioURL := GetBulletinAudioURL(bulletin.ID)

	response := map[string]interface{}{
		"station_id":   bulletin.StationID,
		"station_name": bulletin.StationName,
		"audio_url":    audioURL,
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
	audioURL := GetBulletinAudioURL(int(info.ID))

	response := map[string]interface{}{
		"station_id":   info.Station.ID,
		"station_name": info.Station.Name,
		"audio_url":    audioURL,
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

// GetLatestBulletin returns the most recent bulletin for a station.
func (h *Handlers) GetLatestBulletin(c *gin.Context) {
	stationID, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid station ID")
		return
	}

	// Check if station exists first (using existing helper)
	if !h.stationExists(stationID) {
		responses.NotFound(c, "Station not found")
		return
	}

	// Get the latest bulletin using shared helper function (DRY!)
	bulletin, err := h.getLatestBulletin(stationID, nil)
	if err != nil {
		responses.NotFound(c, "No bulletin found for this station")
		return
	}

	response := h.bulletinToResponse(bulletin)
	responses.Success(c, response)
}

// ListBulletins returns a paginated list of all bulletins with optional filters.
func (h *Handlers) ListBulletins(c *gin.Context) {
	crud := NewCRUDHandler(h.db, "bulletins b",
		WithSelectColumns("b.id, b.station_id, b.filename, b.file_path, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name"),
		WithJoins("JOIN stations s ON b.station_id = s.id"),
		WithOrderBy("b.created_at DESC"))

	filters := map[string]string{
		"b.station_id": "station_id",
	}

	var bulletins []models.Bulletin
	total, err := crud.List(c, &bulletins, filters)
	if err != nil {
		responses.InternalServerError(c, "Failed to fetch bulletins")
		return
	}

	includeStories := c.Query("include_stories") == "true"

	// Convert to response format using existing helper
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

	limit, offset := extractPaginationParams(c)
	responses.Paginated(c, bulletinResponses, total, limit, offset)
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
	storyID, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid story ID")
		return
	}

	// Verify story exists
	var story models.Story
	err = h.db.Get(&story, "SELECT * FROM stories WHERE id = ?", storyID)
	if err != nil {
		responses.NotFound(c, "Story not found")
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
		responses.InternalServerError(c, "Failed to fetch bulletin history")
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

	responses.Success(c, map[string]interface{}{
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

// GetLatestBulletinAudio serves the audio file for the latest bulletin of a station.
func (h *Handlers) GetLatestBulletinAudio(c *gin.Context) {
	stationID, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, "Invalid station ID")
		return
	}

	// Check if station exists first (using existing helper)
	if !h.stationExists(stationID) {
		responses.NotFound(c, "Station not found")
		return
	}

	// Get the latest bulletin using helper function
	bulletin, err := h.getLatestBulletin(stationID, nil)
	if err != nil {
		responses.NotFound(c, "No bulletin found for this station")
		return
	}

	// Add radio automation headers before serving
	c.Header("X-Station-ID", fmt.Sprintf("%d", bulletin.StationID))
	c.Header("X-Bulletin-Duration", fmt.Sprintf("%.2f", bulletin.DurationSeconds))
	c.Header("X-Story-Count", fmt.Sprintf("%d", bulletin.StoryCount))

	// Use existing ServeAudio pattern with bulletin data
	// Override the parameter to use the bulletin ID instead of station ID
	c.Params = append(c.Params[:0], gin.Param{Key: "id", Value: fmt.Sprintf("%d", bulletin.ID)})

	// Leverage existing ServeAudio helper (DRY!)
	h.ServeAudio(c, AudioConfig{
		TableName:   "bulletins",
		IDColumn:    "id",
		FileColumn:  "file_path",
		FilePrefix:  "bulletin",
		ContentType: "audio/wav",
	})
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
