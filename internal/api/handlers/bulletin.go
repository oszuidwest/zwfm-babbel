// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// BulletinAudioURL returns the API URL for downloading a bulletin's audio file.
func BulletinAudioURL(bulletinID int64) string {
	return fmt.Sprintf("/bulletins/%d/audio", bulletinID)
}

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
	bulletinInfo, err := h.bulletinSvc.Create(c.Request.Context(), stationID, targetDate)
	if err != nil {
		h.handleBulletinCreationError(c, err)
		return
	}

	// Serve newly generated bulletin
	h.serveNewBulletin(c, bulletinInfo, download)
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
		serveAudioFile(c, filepath.Join("audio/output", existingBulletin.AudioFile), existingBulletin.Filename, true)
		return true
	}

	// Return existing bulletin metadata
	response := h.bulletinToResponse(existingBulletin)
	utils.Success(c, response)
	return true
}

// serveNewBulletin serves a newly generated bulletin either as audio file or metadata.
func (h *Handlers) serveNewBulletin(c *gin.Context, bulletinInfo *services.BulletinInfo, download bool) {
	// Set cache headers for fresh content
	c.Header("X-Cache", "MISS")
	c.Header("Age", "0")

	if download {
		c.Header("X-Bulletin-Cached", "false")
		c.Header("X-Bulletin-Duration", fmt.Sprintf("%.2f", bulletinInfo.Duration))
		c.Header("X-Bulletin-Stories", fmt.Sprintf("%d", len(bulletinInfo.Stories)))
		serveAudioFile(c, bulletinInfo.BulletinPath, filepath.Base(bulletinInfo.BulletinPath), false)
		return
	}

	// Build response without story list
	response := h.bulletinInfoToResponse(bulletinInfo)
	utils.Success(c, response)
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

// handleBulletinCreationError maps bulletin service errors to appropriate HTTP responses.
func (h *Handlers) handleBulletinCreationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, apperrors.ErrNotFound):
		utils.ProblemNotFound(c, "Station")
	case errors.Is(err, apperrors.ErrNoStoriesAvailable):
		utils.ProblemNotFound(c, "No stories available for the specified date")
	case errors.Is(err, apperrors.ErrAudioProcessingFailed):
		utils.ProblemInternalServer(c, "Failed to generate bulletin audio")
	default:
		utils.ProblemInternalServer(c, "Failed to generate bulletin")
	}
}

// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if !utils.GormValidateBulletinExists(c, h.bulletinSvc.GormDB(), bulletinID) {
		return
	}

	h.bulletinSvc.GetBulletinStoriesWithContext(c)
}

// bulletinToResponse creates a consistent response format for bulletin endpoints
func (h *Handlers) bulletinToResponse(bulletin *models.Bulletin) BulletinResponse {
	bulletinURL := BulletinAudioURL(bulletin.ID)

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
	bulletinURL := BulletinAudioURL(info.ID)

	return BulletinResponse{
		ID:          info.ID,
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
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Check if station exists first
	if !utils.GormValidateStationExists(c, h.bulletinSvc.GormDB(), stationID) {
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

	h.bulletinSvc.GetStationBulletinsWithContext(c)
}

// ListBulletins returns a paginated list of bulletins with modern query parameter support
func (h *Handlers) ListBulletins(c *gin.Context) {
	h.bulletinSvc.ListWithContext(c)
}

// GetStoryBulletinHistory returns paginated list of bulletins that included a specific story.
func (h *Handlers) GetStoryBulletinHistory(c *gin.Context) {
	storyID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	// Check if story exists first
	if !utils.GormValidateStoryExists(c, h.bulletinSvc.GormDB(), storyID) {
		return
	}

	h.bulletinSvc.GetStoryBulletinHistoryWithContext(c)
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
