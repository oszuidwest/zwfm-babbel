// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// BulletinRequest represents the request parameters for bulletin generation.
type BulletinRequest struct {
	StationID int64  `json:"station_id" binding:"required"`
	Date      string `json:"date"`
}

// GenerateBulletin generates a news bulletin for a station.
func (h *Handlers) GenerateBulletin(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
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

	// Try to serve cached bulletin if available
	maxAge := parseCacheControlMaxAge(c.GetHeader("Cache-Control"))
	if !forceNew && maxAge != nil {
		if h.tryServeCachedBulletin(c, stationID, download, maxAge) {
			return
		}
	}

	// Generate new bulletin using service
	bulletinID, err := h.bulletinSvc.Create(c.Request.Context(), stationID, targetDate)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	// Fetch the created bulletin to get complete data with computed fields
	bulletin, err := h.bulletinSvc.GetByID(c.Request.Context(), bulletinID)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	// Serve newly generated bulletin
	h.serveNewBulletin(c, bulletin, download)
}

// parseCacheControlMaxAge extracts max-age duration from Cache-Control header.
// Returns nil if max-age is not present or invalid.
func parseCacheControlMaxAge(cacheControl string) *time.Duration {
	_, after, found := strings.Cut(cacheControl, "max-age=")
	if !found {
		return nil
	}

	maxAgeStr, _, _ := strings.Cut(after, ",")
	maxAgeStr = strings.TrimSpace(maxAgeStr)

	maxAge, err := time.ParseDuration(maxAgeStr + "s")
	if err != nil || maxAge <= 0 {
		return nil
	}

	return &maxAge
}

// tryServeCachedBulletin attempts to serve a cached bulletin if one exists within the max-age.
// Returns true if a cached bulletin was served, false otherwise.
func (h *Handlers) tryServeCachedBulletin(c *gin.Context, stationID int64, download bool, maxAge *time.Duration) bool {
	existingBulletin, err := h.bulletinSvc.GetLatest(c.Request.Context(), stationID, maxAge)
	if err != nil {
		return false
	}

	// Calculate age of the cached bulletin
	age := int(time.Since(existingBulletin.CreatedAt).Seconds())

	// Set standard cache headers
	c.Header("X-Cache", "HIT")
	c.Header("Age", fmt.Sprintf("%d", age))

	if download {
		serveAudioFile(c, utils.BulletinPath(h.config, existingBulletin.AudioFile), existingBulletin.Filename, true)
		return true
	}

	// Return existing bulletin metadata - AfterFind hook populates computed fields
	utils.Success(c, existingBulletin)
	return true
}

// serveNewBulletin serves a newly generated bulletin either as audio file or metadata.
func (h *Handlers) serveNewBulletin(c *gin.Context, bulletin *models.Bulletin, download bool) {
	// Set cache headers for fresh content
	c.Header("X-Cache", "MISS")
	c.Header("Age", "0")

	if download {
		serveAudioFile(c, utils.BulletinPath(h.config, bulletin.AudioFile), bulletin.Filename, false)
		return
	}

	// Return bulletin directly - AfterFind hook populates computed fields
	utils.Success(c, bulletin)
}

// serveAudioFile sets headers and serves an audio file for download.
func serveAudioFile(c *gin.Context, filePath, filename string, cached bool) {
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", "audio/wav")
	c.Header("X-Bulletin-Cached", fmt.Sprintf("%t", cached))
	c.File(filePath)
}

// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	exists, err := h.bulletinSvc.Exists(c.Request.Context(), bulletinID)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Bulletin")
		return
	}

	// Parse query params for pagination (database-level via GORM Limit/Offset)
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	stories, total, err := h.bulletinSvc.GetBulletinStories(c.Request.Context(), bulletinID, params.Limit, params.Offset)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedResponse(c, stories, total, params.Limit, params.Offset)
}

// GetStationBulletins returns bulletins for a specific station with pagination and filtering
func (h *Handlers) GetStationBulletins(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Check if station exists first
	exists, err := h.stationSvc.Exists(c.Request.Context(), stationID)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
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

		// Return directly - AfterFind hook populates computed fields
		utils.Success(c, bulletin)
		return
	}

	query := utils.ParseListQuery(c)
	result, err := h.bulletinSvc.GetStationBulletins(c.Request.Context(), stationID, query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	// Return directly - AfterFind hook populates computed fields
	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// ListBulletins returns a paginated list of bulletins with modern query parameter support
func (h *Handlers) ListBulletins(c *gin.Context) {
	// Parse query parameters
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Convert to repository ListQuery
	query := h.paramsToListQuery(params)

	// Call service
	result, err := h.bulletinSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	// Return directly - AfterFind hook populates computed fields
	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
}

// GetBulletin returns a single bulletin by ID.
func (h *Handlers) GetBulletin(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	bulletin, err := h.bulletinSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	// Return directly - AfterFind hook populates computed fields
	utils.Success(c, bulletin)
}

// GetStoryBulletinHistory returns paginated list of bulletins that included a specific story.
func (h *Handlers) GetStoryBulletinHistory(c *gin.Context) {
	storyID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Check if story exists first
	exists, err := h.storySvc.Exists(c.Request.Context(), storyID)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Story")
		return
	}

	query := utils.ParseListQuery(c)
	result, err := h.bulletinSvc.GetStoryBulletinHistory(c.Request.Context(), storyID, query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	// Return directly - AfterFind hook populates computed fields
	utils.PaginatedResponse(c, result.Data, result.Total, result.Limit, result.Offset)
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
