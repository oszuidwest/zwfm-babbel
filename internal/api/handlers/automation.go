package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// AutomationHandler handles public bulletin requests from radio automation systems.
type AutomationHandler struct {
	bulletinSvc *services.BulletinService
	stationSvc  *services.StationService
	config      *config.Config

	// stationLocks provides per-station mutex to prevent concurrent bulletin generation.
	stationLocks   map[int64]*sync.Mutex
	stationLocksMu sync.Mutex
}

// NewAutomationHandler creates a public automation endpoint handler.
func NewAutomationHandler(bulletinSvc *services.BulletinService, stationSvc *services.StationService, cfg *config.Config) *AutomationHandler {
	return &AutomationHandler{
		bulletinSvc:  bulletinSvc,
		stationSvc:   stationSvc,
		config:       cfg,
		stationLocks: make(map[int64]*sync.Mutex),
	}
}

// getStationLock returns a station mutex, creating it on first use.
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

// bulletinRequest holds validated request parameters for public bulletin endpoint.
type bulletinRequest struct {
	stationID     int64
	maxAgeSeconds int64
}

// validateBulletinRequest parses public automation parameters.
// It writes the error response before returning nil on invalid input; a missing
// automation key deliberately behaves like an absent route.
func (h *AutomationHandler) validateBulletinRequest(c *gin.Context) *bulletinRequest {
	if h.config.Automation.Key == "" {
		utils.ProblemNotFound(c, "Endpoint")
		return nil
	}

	providedKey := c.Query("key")
	if providedKey == "" {
		utils.ProblemAuthentication(c, "API key required")
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(h.config.Automation.Key)) != 1 {
		utils.ProblemAuthentication(c, "Invalid API key")
		return nil
	}

	stationIDStr := c.Param("id")
	stationID, err := strconv.ParseInt(stationIDStr, 10, 64)
	if err != nil || stationID <= 0 {
		utils.ProblemValidationError(c, "Invalid station ID", []apperrors.ValidationError{{
			Field:   "id",
			Message: "Station ID must be a positive integer",
		}})
		return nil
	}

	maxAgeStr := c.Query("max_age")
	if maxAgeStr == "" {
		utils.ProblemValidationError(c, "Missing required parameter", []apperrors.ValidationError{{
			Field:   "max_age",
			Message: "max_age parameter is required (seconds)",
		}})
		return nil
	}
	maxAgeSeconds, err := strconv.ParseInt(maxAgeStr, 10, 64)
	if err != nil || maxAgeSeconds < 0 {
		utils.ProblemValidationError(c, "Invalid parameter", []apperrors.ValidationError{{
			Field:   "max_age",
			Message: "max_age must be a non-negative integer (seconds)",
		}})
		return nil
	}

	return &bulletinRequest{stationID: stationID, maxAgeSeconds: maxAgeSeconds}
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
//   - 200 OK: WAV audio file.
//   - 400 Bad Request: Missing or invalid parameters.
//   - 401 Unauthorized: Invalid API key.
//   - 404 Not Found: Station not found, no stories available, or endpoint disabled.
//   - 500 Internal Server Error: Generation failed.
func (h *AutomationHandler) GetPublicBulletin(c *gin.Context) {
	req := h.validateBulletinRequest(c)
	if req == nil {
		return
	}

	exists, err := h.stationSvc.Exists(c.Request.Context(), req.stationID)
	if err != nil {
		logger.Error("Automation: failed to check station existence", "error", err)
		utils.ProblemInternalServer(c, "Failed to check station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return
	}

	maxAge := time.Duration(req.maxAgeSeconds) * time.Second

	// Fast path: serve a fresh-enough bulletin without the generation lock so
	// cache hits are never serialized behind another client's generation or
	// download speed. This lookup runs on the request context; the generation
	// timeout starts only once the lock is held.
	if req.maxAgeSeconds > 0 {
		existing, ok := h.lookupFreshBulletin(c, c.Request.Context(), req.stationID, maxAge)
		if !ok {
			return
		}
		if existing != nil {
			h.serveBulletinAudio(c, existing.AudioFile, existing.ID, true)
			return
		}
	}

	bulletin, cached, ok := h.getOrGenerateBulletin(c, req, maxAge)
	if !ok {
		return
	}

	h.serveBulletinAudio(c, bulletin.AudioFile, bulletin.ID, cached)
}

// lookupFreshBulletin returns the latest bulletin within maxAge, or nil when
// none exists. On lookup failure it writes the error response and reports
// ok=false.
func (h *AutomationHandler) lookupFreshBulletin(c *gin.Context, ctx context.Context, stationID int64, maxAge time.Duration) (*models.Bulletin, bool) {
	bulletin, err := h.bulletinSvc.GetLatest(ctx, stationID, &maxAge)
	if _, isNotFound := errors.AsType[*apperrors.NotFoundError](err); err != nil && !isNotFound {
		logger.Error("Automation: failed to check existing bulletin", "error", err)
		utils.ProblemInternalServer(c, "Failed to check existing bulletin")
		return nil, false
	}
	return bulletin, true
}

// getOrGenerateBulletin produces a bulletin under the per-station lock, which
// only guards generation. A request that waited on the lock re-checks the
// cache so it reuses the bulletin the lock winner just generated instead of
// generating again. On failure it writes the error response and reports
// ok=false.
func (h *AutomationHandler) getOrGenerateBulletin(c *gin.Context, req *bulletinRequest, maxAge time.Duration) (bulletin *models.Bulletin, cached, ok bool) {
	lock := h.getStationLock(req.stationID)
	lock.Lock()
	defer lock.Unlock()

	// The generation timeout starts after the lock is acquired so time spent
	// waiting behind another generation does not eat into it.
	ctx, cancel := context.WithTimeout(c.Request.Context(), h.config.Automation.GenerationTimeout)
	defer cancel()

	if req.maxAgeSeconds > 0 {
		existing, ok := h.lookupFreshBulletin(c, ctx, req.stationID, maxAge)
		if !ok {
			return nil, false, false
		}
		if existing != nil {
			return existing, true, true
		}
	}

	logger.Info("Automation: generating new bulletin", "station_id", req.stationID, "max_age_s", req.maxAgeSeconds)

	created, err := h.bulletinSvc.Create(ctx, req.stationID, time.Now())
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return nil, false, false
	}
	return created, false, true
}

// serveBulletinAudio sends the bulletin WAV file as response, or the
// appropriate error response when the file is missing or unreadable.
func (h *AutomationHandler) serveBulletinAudio(c *gin.Context, audioFile string, bulletinID int64, cached bool) {
	filePath := utils.BulletinPath(h.config, audioFile)

	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			logger.Error("Automation: audio file not found", "path", filePath)
			utils.ProblemNotFound(c, "Audio file")
		} else {
			logger.Error("Automation: failed to access audio file", "error", err)
			utils.ProblemInternalServer(c, "Failed to access audio file")
		}
		return
	}

	// Automation clients should not cache public bulletin responses.
	c.Header("Cache-Control", "no-store")
	serveAudioFile(c, filePath, audioFile, bulletinID, cached)
}
