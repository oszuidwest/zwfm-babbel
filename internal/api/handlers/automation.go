// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// AutomationHandler handles public bulletin requests from radio automation systems.
type AutomationHandler struct {
	bulletinSvc *services.BulletinService
	stationSvc  *services.StationService
	config      *config.Config

	// stationLocks provides per-station mutex to prevent concurrent bulletin generation
	stationLocks   map[int64]*sync.Mutex
	stationLocksMu sync.Mutex
}

// NewAutomationHandler creates a new automation handler.
func NewAutomationHandler(bulletinSvc *services.BulletinService, stationSvc *services.StationService, cfg *config.Config) *AutomationHandler {
	return &AutomationHandler{
		bulletinSvc:  bulletinSvc,
		stationSvc:   stationSvc,
		config:       cfg,
		stationLocks: make(map[int64]*sync.Mutex),
	}
}

// getStationLock returns a mutex for the given station ID, creating one if it doesn't exist.
func (h *AutomationHandler) getStationLock(stationID int64) *sync.Mutex {
	h.stationLocksMu.Lock()
	defer h.stationLocksMu.Unlock()

	if lock, exists := h.stationLocks[stationID]; exists {
		return lock
	}

	lock := &sync.Mutex{}
	h.stationLocks[stationID] = lock
	return lock
}

// GetPublicBulletin serves bulletin audio for radio automation systems.
// This endpoint is public but requires a valid API key.
//
// GET /public/stations/:id/bulletin.wav?key=xxx&max_age=3600
//
// Query parameters:
//   - key: Required. The automation API key configured in BABBEL_AUTOMATION_KEY.
//   - max_age: Required. Maximum age in seconds. If the latest bulletin is older,
//     a new one will be generated. Use 0 to always generate a fresh bulletin.
//
// Response:
//   - 200 OK: WAV audio file
//   - 400 Bad Request: Missing or invalid parameters
//   - 401 Unauthorized: Invalid API key
//   - 404 Not Found: Station not found, no stories available, or endpoint disabled
//   - 500 Internal Server Error: Generation failed
func (h *AutomationHandler) GetPublicBulletin(c *gin.Context) {
	// Check if automation endpoint is enabled
	if h.config.Automation.Key == "" {
		c.Status(404)
		return
	}

	// Validate API key
	providedKey := c.Query("key")
	if providedKey == "" {
		utils.ProblemAuthentication(c, "API key required")
		return
	}
	if providedKey != h.config.Automation.Key {
		utils.ProblemAuthentication(c, "Invalid API key")
		return
	}

	// Parse station ID
	stationIDStr := c.Param("id")
	stationID, err := strconv.ParseInt(stationIDStr, 10, 64)
	if err != nil || stationID <= 0 {
		utils.ProblemValidationError(c, "Invalid station ID", []utils.ValidationError{{
			Field:   "id",
			Message: "Station ID must be a positive integer",
		}})
		return
	}

	// Parse max_age (required)
	maxAgeStr := c.Query("max_age")
	if maxAgeStr == "" {
		utils.ProblemValidationError(c, "Missing required parameter", []utils.ValidationError{{
			Field:   "max_age",
			Message: "max_age parameter is required (seconds)",
		}})
		return
	}
	maxAgeSeconds, err := strconv.ParseInt(maxAgeStr, 10, 64)
	if err != nil || maxAgeSeconds < 0 {
		utils.ProblemValidationError(c, "Invalid parameter", []utils.ValidationError{{
			Field:   "max_age",
			Message: "max_age must be a non-negative integer (seconds)",
		}})
		return
	}

	// Check if station exists
	exists, err := h.stationSvc.Exists(c.Request.Context(), stationID)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return
	}

	// Acquire per-station lock to prevent concurrent generation
	lock := h.getStationLock(stationID)
	lock.Lock()
	defer lock.Unlock()

	// Create context with timeout for bulletin generation
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.config.Automation.GenerationTimeout)
	defer cancel()

	// Check if we have a recent enough bulletin
	maxAge := time.Duration(maxAgeSeconds) * time.Second
	if maxAgeSeconds > 0 {
		existingBulletin, err := h.bulletinSvc.GetLatest(ctx, stationID, &maxAge)
		if err == nil && existingBulletin != nil {
			// Serve cached bulletin
			h.serveBulletinAudio(c, existingBulletin.AudioFile, true)
			return
		}
	}

	// Generate new bulletin
	logger.Info("Automation: generating new bulletin for station %d (max_age=%ds)", stationID, maxAgeSeconds)

	bulletinInfo, err := h.bulletinSvc.Create(ctx, stationID, time.Now())
	if err != nil {
		h.handleGenerationError(c, err)
		return
	}

	// Serve newly generated bulletin
	h.serveBulletinAudio(c, filepath.Base(bulletinInfo.BulletinPath), false)
}

// serveBulletinAudio sends the bulletin WAV file as response.
func (h *AutomationHandler) serveBulletinAudio(c *gin.Context, audioFile string, cached bool) {
	filePath := filepath.Join(h.config.Audio.OutputPath, audioFile)

	// Set headers
	c.Header("Content-Type", "audio/wav")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", audioFile))
	c.Header("Cache-Control", "no-store")
	c.Header("X-Bulletin-Cached", fmt.Sprintf("%t", cached))

	c.File(filePath)
}

// handleGenerationError maps generation errors to appropriate HTTP responses.
func (h *AutomationHandler) handleGenerationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		utils.ProblemInternalServer(c, "Bulletin generation timed out")
	case errors.Is(err, apperrors.ErrNotFound):
		utils.ProblemNotFound(c, "Station")
	case errors.Is(err, apperrors.ErrNoStoriesAvailable):
		utils.ProblemNotFound(c, "No stories available for bulletin generation")
	case errors.Is(err, apperrors.ErrAudioProcessingFailed):
		utils.ProblemInternalServer(c, "Failed to generate bulletin audio")
	default:
		logger.Error("Automation: bulletin generation failed: %v", err)
		utils.ProblemInternalServer(c, "Failed to generate bulletin")
	}
}
