// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
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

	// Parse date
	targetDate, err := services.ParseTargetDate(req.Date)
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []utils.ValidationError{{
			Field:   "date",
			Message: "Invalid date format, use YYYY-MM-DD",
		}})
		return
	}

	// Check HTTP headers for modern behavior
	forceNew := c.GetHeader("Cache-Control") == "no-cache"
	download := c.GetHeader("Accept") == "audio/wav"

	// Parse max-age from Cache-Control header
	var maxAgeStr string
	cacheControl := c.GetHeader("Cache-Control")
	if strings.Contains(cacheControl, "max-age=") {
		parts := strings.Split(cacheControl, "max-age=")
		if len(parts) > 1 {
			maxAgeStr = strings.Split(parts[1], ",")[0]
			maxAgeStr = strings.TrimSpace(maxAgeStr)
		}
	}

	// Check if we should return existing bulletin
	if !forceNew && maxAgeStr != "" {
		maxAge, err := time.ParseDuration(maxAgeStr + "s")
		if err == nil && maxAge > 0 {
			// Check for existing bulletin within cache time limit
			existingBulletin, err := h.bulletinSvc.GetLatest(c.Request.Context(), stationID, &maxAge)
			if err == nil {
				// Calculate age of the cached bulletin
				age := int(time.Since(existingBulletin.CreatedAt).Seconds())

				// Set standard cache headers
				c.Header("X-Cache", "HIT")
				c.Header("Age", fmt.Sprintf("%d", age))

				// Handle download if requested
				if download {
					c.Header("Content-Description", "File Transfer")
					c.Header("Content-Transfer-Encoding", "binary")
					c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", existingBulletin.Filename))
					c.Header("Content-Type", "audio/wav")
					c.Header("X-Bulletin-Cached", "true")
					c.File(filepath.Join("audio/output", existingBulletin.AudioFile))
					return
				}

				// Return existing bulletin metadata
				response := h.bulletinToResponse(existingBulletin)
				utils.Success(c, response)
				return
			}
		}
	}

	// Generate new bulletin using service
	bulletinInfo, err := h.bulletinSvc.Create(c.Request.Context(), stationID, targetDate)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNotFound):
			utils.ProblemNotFound(c, "Station")
		case errors.Is(err, services.ErrNoStoriesAvailable):
			utils.ProblemNotFound(c, "No stories available for the specified date")
		case errors.Is(err, services.ErrAudioProcessingFailed):
			utils.ProblemInternalServer(c, "Failed to generate bulletin audio")
		default:
			utils.ProblemInternalServer(c, "Failed to generate bulletin")
		}
		return
	}

	// Set cache headers for fresh content
	c.Header("X-Cache", "MISS")
	c.Header("Age", "0")

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

	// Build response without story list
	response := h.bulletinInfoToResponse(bulletinInfo)
	utils.Success(c, response)
}

// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	if !utils.ValidateBulletinExists(c, h.db, bulletinID) {
		return
	}

	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT bs.*, s.title as story_title, st.name as station_name, 
				b.filename as bulletin_filename, b.station_id
				FROM bulletin_stories bs
				JOIN stories s ON bs.story_id = s.id
				JOIN bulletins b ON bs.bulletin_id = b.id  
				JOIN stations st ON b.station_id = st.id`,
			CountQuery: `SELECT COUNT(*) FROM bulletin_stories bs 
				JOIN stories s ON bs.story_id = s.id 
				JOIN bulletins b ON bs.bulletin_id = b.id`,
			DefaultOrder: "bs.story_order ASC",
			Filters: []utils.FilterConfig{{
				Column: "bulletin_id", Table: "bs", Value: bulletinID,
			}},
			PostProcessor: func(result interface{}) {
				if stories, ok := result.(*[]models.BulletinStory); ok {
					processed := make([]BulletinStoryResponse, len(*stories))
					for i, bs := range *stories {
						processed[i] = BulletinStoryResponse{
							ID:         bs.ID,
							BulletinID: bs.BulletinID,
							StoryID:    bs.StoryID,
							StoryOrder: bs.StoryOrder,
							CreatedAt:  bs.CreatedAt,
							Station: StationRef{
								ID:   bs.StationID,
								Name: bs.StationName,
							},
							Story: StoryRef{
								ID:    bs.StoryID,
								Title: bs.StoryTitle,
							},
							Bulletin: BulletinRef{
								ID:       bs.BulletinID,
								Filename: bs.BulletinFilename,
							},
						}
					}
					c.Set("processed_bulletin_stories", processed)
				}
			},
		},
		SearchFields: []string{"s.title"},
		FieldMapping: map[string]string{
			"story_order": "bs.story_order", "story_title": "s.title",
		},
	}

	var bulletinStories []models.BulletinStory
	utils.ModernListWithQuery(c, h.db, config, &bulletinStories)
}

// bulletinToResponse creates a consistent response format for bulletin endpoints
func (h *Handlers) bulletinToResponse(bulletin *models.Bulletin) BulletinResponse {
	bulletinURL := GetBulletinAudioURL(bulletin.ID)

	return BulletinResponse{
		ID:          bulletin.ID,
		StationID:   bulletin.StationID,
		StationName: bulletin.StationName,
		AudioURL:    bulletinURL,
		Filename:    bulletin.Filename,
		CreatedAt:   bulletin.CreatedAt,
		Duration:    bulletin.DurationSeconds,
		FileSize:    bulletin.FileSize,
		StoryCount:  bulletin.StoryCount,
	}
}

// bulletinInfoToResponse creates response from BulletinInfo
func (h *Handlers) bulletinInfoToResponse(info *services.BulletinInfo) BulletinResponse {
	bulletinURL := GetBulletinAudioURL(int(info.ID))

	return BulletinResponse{
		ID:          int(info.ID),
		StationID:   info.Station.ID,
		StationName: info.Station.Name,
		AudioURL:    bulletinURL,
		Filename:    filepath.Base(info.BulletinPath),
		CreatedAt:   info.CreatedAt,
		Duration:    info.Duration,
		FileSize:    info.FileSize,
		StoryCount:  len(info.Stories),
	}
}

// GetStationBulletins returns bulletins for a specific station with pagination and filtering
func (h *Handlers) GetStationBulletins(c *gin.Context) {
	stationID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if station exists first
	if !utils.ValidateStationExists(c, h.db, stationID) {
		return
	}

	// Check for 'latest' query parameter for RESTful latest bulletin access
	if c.Query("latest") == "true" || c.Query("limit") == "1" {
		bulletin, err := h.bulletinSvc.GetLatest(c.Request.Context(), stationID, nil)
		if err != nil {
			utils.ProblemNotFound(c, "No bulletin found for this station")
			return
		}

		// Set cache headers indicating this is existing content
		age := int(time.Since(bulletin.CreatedAt).Seconds())
		c.Header("X-Cache", "HIT")
		c.Header("Age", fmt.Sprintf("%d", age))

		response := h.bulletinToResponse(bulletin)
		utils.Success(c, response)
		return
	}

	// Configure modern query with field mappings, search fields, and station_id filter
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds, 
			            b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name
			            FROM bulletins b 
			            JOIN stations s ON b.station_id = s.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletins b JOIN stations s ON b.station_id = s.id",
			DefaultOrder: "b.created_at DESC",
			PostProcessor: func(result interface{}) {
				// Post-process bulletins to add audio URLs
				if bulletins, ok := result.(*[]BulletinListResponse); ok {
					for i := range *bulletins {
						(*bulletins)[i].AudioURL = GetBulletinAudioURL((*bulletins)[i].ID)
					}
				}
			},
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
		DefaultFields:     "b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name",
		DisableSoftDelete: true, // Bulletins table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":               "b.id",
			"station_id":       "b.station_id",
			"filename":         "b.filename",
			"audio_file":       "b.audio_file",
			"duration_seconds": "b.duration_seconds",
			"duration":         "b.duration_seconds", // Allow both field names
			"file_size":        "b.file_size",
			"story_count":      "b.story_count",
			"metadata":         "b.metadata",
			"created_at":       "b.created_at",
			"station_name":     "s.name",
		},
	}

	var bulletins []BulletinListResponse
	utils.ModernListWithQuery(c, h.db, config, &bulletins)
}

// BulletinListResponse represents the response format for bulletins in list view with computed fields.
type BulletinListResponse struct {
	models.Bulletin
	AudioURL string `json:"audio_url,omitempty"`
}

// ListBulletins returns a paginated list of bulletins with modern query parameter support
func (h *Handlers) ListBulletins(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds, 
			            b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name
			            FROM bulletins b 
			            JOIN stations s ON b.station_id = s.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletins b JOIN stations s ON b.station_id = s.id",
			DefaultOrder: "b.created_at DESC",
			PostProcessor: func(result interface{}) {
				// Post-process bulletins to add audio URLs
				if bulletins, ok := result.(*[]BulletinListResponse); ok {
					for i := range *bulletins {
						(*bulletins)[i].AudioURL = GetBulletinAudioURL((*bulletins)[i].ID)
					}
				}
			},
		},
		SearchFields:      []string{"b.filename", "s.name"},
		TableAlias:        "b",
		DefaultFields:     "b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name",
		DisableSoftDelete: true, // Bulletins table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":               "b.id",
			"station_id":       "b.station_id",
			"filename":         "b.filename",
			"audio_file":       "b.audio_file",
			"duration_seconds": "b.duration_seconds",
			"duration":         "b.duration_seconds", // Allow both field names
			"file_size":        "b.file_size",
			"story_count":      "b.story_count",
			"metadata":         "b.metadata",
			"created_at":       "b.created_at",
			"station_name":     "s.name",
		},
	}

	var bulletins []BulletinListResponse
	utils.ModernListWithQuery(c, h.db, config, &bulletins)
}

// GetStoryBulletinHistory returns paginated list of bulletins that included a specific story.
func (h *Handlers) GetStoryBulletinHistory(c *gin.Context) {
	storyID, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check if story exists first
	if !utils.ValidateStoryExists(c, h.db, storyID) {
		return
	}

	// Configure modern query with field mappings, search fields, and story_id filter
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery: `SELECT b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds,
			            b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name,
			            bs.story_order, bs.created_at as included_at
			            FROM bulletin_stories bs
			            JOIN bulletins b ON bs.bulletin_id = b.id
			            JOIN stations s ON b.station_id = s.id`,
			CountQuery:   "SELECT COUNT(*) FROM bulletin_stories bs JOIN bulletins b ON bs.bulletin_id = b.id JOIN stations s ON b.station_id = s.id",
			DefaultOrder: "bs.created_at DESC",
			Filters: []utils.FilterConfig{
				{
					Column: "story_id",
					Table:  "bs",
					Value:  storyID,
				},
			},
			PostProcessor: func(result interface{}) {
				bulletinHistory := result.(*[]models.StoryBulletinHistory)
				// Convert to the expected response format
				processedResults := make([]StoryBulletinHistoryResponse, len(*bulletinHistory))
				for i, item := range *bulletinHistory {
					baseResponse := h.bulletinToResponse(&item.Bulletin)
					processedResults[i] = StoryBulletinHistoryResponse{
						BulletinResponse: baseResponse,
						StoryOrder:       item.StoryOrder,
						IncludedAt:       item.IncludedAt,
					}
				}
				// Store processed results in context for later retrieval
				c.Set("processed_results", processedResults)
			},
		},
		SearchFields:      []string{"b.filename", "s.name"},
		TableAlias:        "bs",
		DefaultFields:     "b.id, b.station_id, b.filename, b.audio_file, b.duration_seconds, b.file_size, b.story_count, b.metadata, b.created_at, s.name as station_name, bs.story_order, bs.created_at as included_at",
		DisableSoftDelete: true, // bulletin_stories table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":               "b.id",
			"bulletin_id":      "b.id",
			"station_id":       "b.station_id",
			"filename":         "b.filename",
			"audio_file":       "b.audio_file",
			"duration_seconds": "b.duration_seconds",
			"duration":         "b.duration_seconds", // Allow both field names
			"file_size":        "b.file_size",
			"story_count":      "b.story_count",
			"metadata":         "b.metadata",
			"created_at":       "b.created_at",
			"station_name":     "s.name",
			"story_order":      "bs.story_order",
			"included_at":      "bs.created_at",
		},
	}

	var bulletinHistory []models.StoryBulletinHistory
	utils.ModernListWithQuery(c, h.db, config, &bulletinHistory)

	// Check if ModernListWithQuery already handled the response (error case)
	if c.IsAborted() {
		return
	}

	// Check if we have processed results from PostProcessor
	if processedResults, exists := c.Get("processed_results"); exists {
		// Get pagination data
		responseData, exists := c.Get("pagination_data")
		if !exists {
			utils.ProblemInternalServer(c, "Pagination data not found")
			return
		}
		paginationInfo, ok := responseData.(map[string]interface{})
		if !ok {
			utils.ProblemInternalServer(c, "Failed to get pagination data")
			return
		}

		// Extract pagination values with type assertions
		total, ok := paginationInfo["total"].(int64)
		if !ok {
			utils.ProblemInternalServer(c, "Invalid pagination total")
			return
		}
		limit, ok := paginationInfo["limit"].(int)
		if !ok {
			utils.ProblemInternalServer(c, "Invalid pagination limit")
			return
		}
		offset, ok := paginationInfo["offset"].(int)
		if !ok {
			utils.ProblemInternalServer(c, "Invalid pagination offset")
			return
		}

		// Send the processed paginated response
		utils.PaginatedResponse(c, processedResults, total, limit, offset)
		return
	}

	// Fallback if PostProcessor didn't run (shouldn't happen)
	utils.ProblemInternalServer(c, "Failed to process story bulletin history")
}

// GetBulletinAudio serves the audio file for a specific bulletin.
func (h *Handlers) GetBulletinAudio(c *gin.Context) {
	h.ServeAudio(c, AudioConfig{
		TableName:   "bulletins",
		IDColumn:    "id",
		FileColumn:  "audio_file",
		FilePrefix:  "bulletin",
		ContentType: "audio/wav",
		Directory:   "output",
	})
}
