package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// AutomationHandler handles public bulletin requests from radio automation systems.
type AutomationHandler struct {
	bulletinSvc *services.BulletinService
	stationSvc  *services.StationService
	config      *config.Config
	alerts      notify.Alerter
}

// NewAutomationHandler creates a public automation endpoint handler.
func NewAutomationHandler(bulletinSvc *services.BulletinService, stationSvc *services.StationService, cfg *config.Config, alerts notify.Alerter) *AutomationHandler {
	return &AutomationHandler{
		bulletinSvc: bulletinSvc,
		stationSvc:  stationSvc,
		config:      cfg,
		alerts:      notify.OrDiscard(alerts),
	}
}

type bulletinRequest struct {
	stationID     int64
	maxAgeSeconds int64
}

// validateBulletinRequest authenticates and parses automation parameters.
// On failure it writes an error response and returns nil.
// An unset automation key disables the endpoint with a 404.
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
		h.alerts.Alert(c.Request.Context(), notify.Event{
			Key:               "security:automation-key",
			Summary:           "Repeated invalid radio automation keys",
			Details:           "Multiple requests to the public bulletin endpoint used an invalid key. The provided key is never logged or e-mailed.",
			RequiresThreshold: true,
		})
		utils.ProblemAuthentication(c, "Invalid API key")
		return nil
	}
	h.alerts.Resolve(c.Request.Context(), "security:automation-key",
		"Radio automation key accepted again", "A request supplied the configured radio automation key.")

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

// GetPublicBulletin serves API-key-authenticated audio to automation clients.
// max_age=0 forces generation; larger values permit a fresh cached bulletin.
func (h *AutomationHandler) GetPublicBulletin(c *gin.Context) {
	req := h.validateBulletinRequest(c)
	if req == nil {
		return
	}

	exists, err := h.stationSvc.Exists(c.Request.Context(), req.stationID)
	if err != nil {
		logger.Error("Automation: failed to check station existence", "error", err)
		h.alerts.Alert(c.Request.Context(), databaseRequestEvent(c, err.Error()))
		utils.ProblemInternalServer(c, "Failed to check station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return
	}

	maxAge := time.Duration(req.maxAgeSeconds) * time.Second

	// Cache hits bypass the generation lock to avoid waiting for other requests.
	if req.maxAgeSeconds > 0 {
		existing, ok := h.lookupFreshBulletin(c, c.Request.Context(), req.stationID, maxAge)
		if !ok {
			return
		}
		if existing != nil {
			h.serveBulletinAudio(c, existing.AudioFile, existing.ID, req.stationID, true)
			return
		}
	}

	bulletin, cached, ok := h.getOrGenerateBulletin(c, req, maxAge)
	if !ok {
		return
	}

	h.serveBulletinAudio(c, bulletin.AudioFile, bulletin.ID, req.stationID, cached)
}

// lookupFreshBulletin returns the latest bulletin within maxAge, or nil if absent.
// On failure it writes an error response and returns false.
func (h *AutomationHandler) lookupFreshBulletin(c *gin.Context, ctx context.Context, stationID int64, maxAge time.Duration) (*models.Bulletin, bool) {
	bulletin, err := h.bulletinSvc.GetLatest(ctx, stationID, &maxAge)
	if _, isNotFound := errors.AsType[*apperrors.NotFoundError](err); err != nil && !isNotFound {
		logger.Error("Automation: failed to check existing bulletin", "error", err)
		h.alerts.Alert(ctx, databaseRequestEvent(c, err.Error()))
		utils.ProblemInternalServer(c, "Failed to check existing bulletin")
		return nil, false
	}
	return bulletin, true
}

// getOrGenerateBulletin rechecks the cache and generates under a per-station lock.
// The lock is released before delivery. On failure it writes an error response
// and returns ok=false.
func (h *AutomationHandler) getOrGenerateBulletin(c *gin.Context, req *bulletinRequest, maxAge time.Duration) (bulletin *models.Bulletin, cached, ok bool) {
	waitCtx, cancelWait := context.WithTimeout(c.Request.Context(), h.config.Automation.GenerationTimeout)
	release, err := h.bulletinSvc.LockStation(waitCtx, req.stationID)
	cancelWait()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("Automation: timed out waiting for station lock", "station_id", req.stationID, "waited", h.config.Automation.GenerationTimeout)
			utils.ProblemExtended(c, http.StatusGatewayTimeout, "Timed out waiting for bulletin generation", apperrors.CodeTimeout, "Retry the request")
		} else {
			utils.ProblemInternalServer(c, "Bulletin generation was interrupted")
		}
		return nil, false, false
	}
	defer release()

	// Lock waiting must not consume the generation timeout.
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

// serveBulletinAudio serves bulletin audio and reports availability and delivery failures.
func (h *AutomationHandler) serveBulletinAudio(c *gin.Context, audioFile string, bulletinID, stationID int64, cached bool) {
	filePath := utils.BulletinPath(h.config, audioFile)
	// A station key lets a later bulletin resolve the same alert.
	alertKey := "bulletin:served-audio:station:" + strconv.FormatInt(stationID, 10)

	if _, err := os.Stat(filePath); err != nil {
		h.alerts.Alert(c.Request.Context(), notify.Event{
			Key:     alertKey,
			Summary: "Radio automation bulletin file is unavailable",
			Details: "Bulletin " + strconv.FormatInt(bulletinID, 10) + " could not be served from " + filePath + ": " + err.Error(),
		})
		if os.IsNotExist(err) {
			logger.Error("Automation: audio file not found", "path", filePath)
			utils.ProblemNotFound(c, "Audio file")
		} else {
			logger.Error("Automation: failed to access audio file", "error", err)
			utils.ProblemInternalServer(c, "Failed to access audio file")
		}
		return
	}
	h.alerts.Resolve(c.Request.Context(), alertKey,
		"Radio automation bulletin file recovered", "Bulletin audio is readable again.")

	c.Header("Cache-Control", "no-store")
	deliveryKey := "bulletin:delivery:station:" + strconv.FormatInt(stationID, 10)
	if err := serveAudioFile(c, filePath, audioFile, bulletinID, cached); err != nil {
		logger.Error("Automation: failed to deliver bulletin audio", "station_id", stationID, "bulletin_id", bulletinID, "error", err)
		h.alerts.Alert(context.WithoutCancel(c.Request.Context()), notify.Event{
			Key: deliveryKey, Summary: "Radio automation bulletin delivery failed",
			Details: fmt.Sprintf("Bulletin %d for station %d could not be fully written: %v", bulletinID, stationID, err),
		})
		return
	}
	if c.Writer.Status() == http.StatusOK || c.Writer.Status() == http.StatusPartialContent {
		h.alerts.Resolve(c.Request.Context(), deliveryKey, "Radio automation bulletin delivery recovered", "Bulletin audio was written successfully again.")
	}
}
