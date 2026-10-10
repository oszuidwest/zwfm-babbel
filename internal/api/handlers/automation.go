package handlers

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
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

// maxMaxAgeSeconds keeps max_age within time.Duration.
const maxMaxAgeSeconds = math.MaxInt64 / int64(time.Second)

// parseMaxAge parses the required max_age query parameter in seconds.
func parseMaxAge(raw string) (int64, *apperrors.FieldError) {
	invalid := func(code, message string) (int64, *apperrors.FieldError) {
		return 0, &apperrors.FieldError{Field: "max_age", Code: code, Message: message}
	}
	if raw == "" {
		return invalid(apperrors.CodeRequired, "max_age is required (seconds)")
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	switch {
	case err != nil && !errors.Is(err, strconv.ErrRange):
		return invalid(apperrors.CodeInvalidFormat, fmt.Sprintf("expected integer, got %q", raw))
	case err != nil || seconds < 0 || seconds > maxMaxAgeSeconds:
		return invalid(apperrors.CodeOutOfRange, fmt.Sprintf("must be between 0 and %d seconds", maxMaxAgeSeconds))
	}
	return seconds, nil
}

type bulletinRequest struct {
	stationID     int64
	maxAgeSeconds int64
}

// validateBulletinRequest authenticates and parses automation parameters.
// It writes an error response and returns nil on failure, including 404 if no key is configured.
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

	stationID, ok := utils.IDParam(c)
	if !ok {
		return nil
	}

	maxAgeSeconds, fieldErr := parseMaxAge(c.Query("max_age"))
	if fieldErr != nil {
		utils.ProblemQueryValidation(c, "Invalid query parameter", []apperrors.FieldError{*fieldErr})
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

	// Cache hits bypass the generation lock.
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

// lookupFreshBulletin returns the latest bulletin within maxAge, or nil.
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
// It releases the lock before returning and writes an error response if ok is false.
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

	created, err := h.bulletinSvc.Create(ctx, req.stationID)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return nil, false, false
	}
	return created, false, true
}

// serveBulletinAudio serves bulletin audio and reports availability and delivery failures.
func (h *AutomationHandler) serveBulletinAudio(c *gin.Context, audioFile string, bulletinID, stationID int64, cached bool) {
	filePath := utils.BulletinPath(h.config, audioFile)
	// Station keys allow alert recovery across bulletins.
	station := strconv.FormatInt(stationID, 10)
	alertKey := "bulletin:served-audio:station:" + station

	file, err := os.Open(filePath) //nolint:gosec // Path uses the configured storage root and stored file names.
	if err != nil {
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
	defer func() { _ = file.Close() }() // Read-only; close errors cannot affect the response.
	h.alerts.Resolve(c.Request.Context(), alertKey,
		"Radio automation bulletin file recovered", "Bulletin audio is readable again.")

	c.Header("Cache-Control", "no-store")
	deliveryKey := "bulletin:delivery:station:" + station
	if err := serveAudioFile(c, file, audioFile, bulletinID, cached); err != nil {
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
