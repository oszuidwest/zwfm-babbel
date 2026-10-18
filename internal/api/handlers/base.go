// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// HandlersDeps groups dependencies resolved during router setup.
type HandlersDeps struct {
	AudioRepo             repository.AudioRepository
	Config                *config.Config
	BulletinSvc           *services.BulletinService
	BulletinJobSvc        *services.BulletinJobService
	StorySvc              *services.StoryService
	StationSvc            *services.StationService
	VoiceSvc              *services.VoiceService
	UserSvc               *services.UserService
	StationVoiceSvc       *services.StationVoiceService
	TTSSettingsSvc        *services.TTSSettingsService
	PronunciationRulesSvc *services.PronunciationRulesService
	TTSEnabled            bool
}

// Handlers owns shared dependencies used by endpoint methods.
type Handlers struct {
	audioRepo             repository.AudioRepository
	config                *config.Config
	bulletinSvc           *services.BulletinService
	bulletinJobSvc        *services.BulletinJobService
	storySvc              *services.StoryService
	stationSvc            *services.StationService
	voiceSvc              *services.VoiceService
	userSvc               *services.UserService
	stationVoiceSvc       *services.StationVoiceService
	ttsSettingsSvc        *services.TTSSettingsService
	pronunciationRulesSvc pronunciationRulesService
	ttsEnabled            bool
}

// NewHandlers creates endpoint handlers from resolved dependencies.
func NewHandlers(deps HandlersDeps) *Handlers {
	return &Handlers{
		audioRepo:             deps.AudioRepo,
		config:                deps.Config,
		bulletinSvc:           deps.BulletinSvc,
		bulletinJobSvc:        deps.BulletinJobSvc,
		storySvc:              deps.StorySvc,
		stationSvc:            deps.StationSvc,
		voiceSvc:              deps.VoiceSvc,
		userSvc:               deps.UserSvc,
		stationVoiceSvc:       deps.StationVoiceSvc,
		ttsSettingsSvc:        deps.TTSSettingsSvc,
		pronunciationRulesSvc: deps.PronunciationRulesSvc,
		ttsEnabled:            deps.TTSEnabled,
	}
}

// handleServiceError maps domain errors to RFC 9457 Problem Details responses.
func handleServiceError(c *gin.Context, err error, fallbackResource string) {
	// Timeouts take precedence over wrapped domain errors.
	if errors.Is(err, context.DeadlineExceeded) {
		logRequestTimeout(c, err, fallbackResource)
		utils.ProblemExtended(c, http.StatusGatewayTimeout,
			fmt.Sprintf("%s operation timed out", fallbackResource),
			apperrors.CodeTimeout,
			"The request took too long. Please try again.",
		)
		return
	}

	// A client that went away cancels the request context, and the database
	// driver then returns context.Canceled. That is not a server failure. An
	// expired request deadline is not a disconnect, so it keeps the handling
	// below.
	if errors.Is(err, context.Canceled) && errors.Is(c.Request.Context().Err(), context.Canceled) {
		logError(fallbackResource, "client_canceled", err)
		c.AbortWithStatus(statusClientClosedRequest)
		return
	}

	if handleQueryShapeError(c, err) {
		return
	}

	if notFound, ok := errors.AsType[*apperrors.NotFoundError](err); ok {
		logError(notFound.Resource, "not_found", err)
		utils.ProblemExtended(c, http.StatusNotFound,
			notFound.Error(),
			strings.ToLower(notFound.Resource)+".not_found",
			"Check that the ID exists and you have access",
		)
		return
	}

	if duplicate, ok := errors.AsType[*apperrors.DuplicateError](err); ok {
		logErrorWithCause(duplicate.Resource, "duplicate", err, duplicate.Unwrap())
		hint := "Use a different value"
		if duplicate.Field != "" {
			hint = fmt.Sprintf("Use a different %s or update the existing %s",
				duplicate.Field, strings.ToLower(duplicate.Resource))
		}
		utils.ProblemExtended(c, http.StatusConflict,
			duplicate.Error(),
			strings.ToLower(duplicate.Resource)+".duplicate",
			hint,
		)
		return
	}

	if dependency, ok := errors.AsType[*apperrors.DependencyError](err); ok {
		logErrorWithCause(dependency.Resource, "has_dependencies", err, dependency.Unwrap())
		utils.ProblemExtended(c, http.StatusConflict,
			dependency.Error(),
			strings.ToLower(dependency.Resource)+".has_dependencies",
			fmt.Sprintf("Delete or reassign the associated %s first", dependency.Dependency),
		)
		return
	}

	if validation, ok := errors.AsType[*apperrors.ValidationError](err); ok {
		logErrorWithCause(strings.ToLower(fallbackResource), "validation_failed", err, validation.Unwrap())
		utils.ProblemValidationError(c, "The request contains invalid data", validation.Errors...)
		return
	}

	if conflict, ok := errors.AsType[*apperrors.ConflictError](err); ok {
		logErrorWithCause(strings.ToLower(fallbackResource), "conflict", err, conflict.Unwrap())
		utils.ProblemExtended(c, http.StatusConflict, conflict.Message, conflict.Code, conflict.Hint)
		return
	}

	if handleAvailabilityError(c, err) {
		return
	}

	if noStories, ok := errors.AsType[*apperrors.NoStoriesError](err); ok {
		logError("bulletin", "no_stories", err)
		utils.ProblemExtended(c, http.StatusConflict,
			noStories.Error(),
			apperrors.CodeBulletinNoStories,
			"Add active stories with audio before generating a bulletin",
		)
		return
	}

	if handleAudioError(c, err) {
		return
	}

	if dbError, ok := errors.AsType[*apperrors.DatabaseError](err); ok {
		logErrorWithCause(dbError.Resource, "database_error", err, dbError.Unwrap())
		alertDatabaseFailure(c, dbError)
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"An internal error occurred",
			"internal.database_error",
			"Please try again later",
		)
		return
	}

	logger.Error("Unhandled error", "resource", fallbackResource, "error", err)
	alertRequestFailure(c, notify.Event{
		Key:               internalAlertKeyPrefix + utils.RouteKey(c),
		Summary:           "Unhandled API errors repeatedly occur",
		Details:           fmt.Sprintf("Route %s, resource %s: %v", utils.RouteKey(c), fallbackResource, err),
		RequiresThreshold: true,
	})
	utils.ProblemExtended(c, http.StatusInternalServerError,
		fmt.Sprintf("Failed to process %s", fallbackResource),
		"internal.unknown_error",
		"Please try again later or contact support",
	)
}

// alertAudioFailure counts a server-side upload processing failure toward the
// route's audio incident. Bulletin generation (bulletin:generation:*) and TTS
// synthesis (tts:*) alert in their services.
func alertAudioFailure(c *gin.Context, audioError *apperrors.AudioError) {
	if audioError.Resource == "Bulletin" || audioError.Operation == "tts_generate" {
		return
	}
	alertRequestFailure(c, notify.Event{
		Key:               audioAlertKeyPrefix + utils.RouteKey(c),
		Summary:           "Audio processing requests repeatedly fail",
		Details:           fmt.Sprintf("Route %s, resource %s: %v", utils.RouteKey(c), audioError.Resource, audioError.Unwrap()),
		RequiresThreshold: true,
	})
}

func alertDatabaseFailure(c *gin.Context, dbError *apperrors.DatabaseError) {
	alertRequestFailure(c, databaseRequestEvent(c,
		fmt.Sprintf("Route %s, resource %s: %v", utils.RouteKey(c), dbError.Resource, dbError.Unwrap())))
}

func logRequestTimeout(c *gin.Context, err error, resource string) {
	cause := errors.Unwrap(err)
	if cause == nil {
		cause = err
	}
	if dbError, ok := errors.AsType[*apperrors.DatabaseError](err); ok {
		resource, cause = dbError.Resource, dbError.Unwrap()
		alertDatabaseFailure(c, dbError)
	}
	// An upload's audio timeout, such as a hung ffprobe, also counts toward
	// the route's audio incident.
	if audioError, ok := errors.AsType[*apperrors.AudioError](err); ok {
		alertAudioFailure(c, audioError)
	}
	logger.Error("Request timeout", "resource", resource, "error_type", "timeout",
		"route", utils.RouteKey(c), "error", err, "cause", cause)
}

// handleAudioError reports whether it wrote an audio error response.
func handleAudioError(c *gin.Context, err error) bool {
	if audioError, ok := errors.AsType[*apperrors.AudioError](err); ok {
		logErrorWithCause(audioError.Resource, "audio_failed", err, audioError.Unwrap())
		alertAudioFailure(c, audioError)
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"Audio processing failed",
			apperrors.CodeAudioProcessingFailed,
			"Please try again later or contact support",
		)
		return true
	}
	return false
}

// statusClientClosedRequest is the non-standard status that nginx logs for a
// request whose client closed the connection. The client never reads it; it
// keeps the request out of the 5xx counts and, as a status of 400 or higher,
// stops NotificationMiddleware from resolving the route's alerts.
const statusClientClosedRequest = 499

const (
	alertContextKey = "babbel.operational-alerts"

	// Alert key prefixes shared between failure events and the per-route
	// Resolve calls in NotificationMiddleware.
	databaseAlertKeyPrefix = "database:request:"
	internalAlertKeyPrefix = "http:internal:"
	audioAlertKeyPrefix    = "audio:request:"
)

// databaseRequestEvent builds the shared alert for failing database-backed
// requests; NotificationMiddleware resolves it on the route's next success.
func databaseRequestEvent(c *gin.Context, details string) notify.Event {
	return notify.Event{
		Key:               databaseAlertKeyPrefix + utils.RouteKey(c),
		Summary:           "Database requests repeatedly fail",
		Details:           details,
		RequiresThreshold: true,
	}
}

// NotificationMiddleware provides request alerts and resolves them on successful responses.
// A nil alerter disables notifications.
func NotificationMiddleware(alerts notify.Alerter) gin.HandlerFunc {
	alerts = notify.OrDiscard(alerts)
	return func(c *gin.Context) {
		c.Set(alertContextKey, alerts)
		c.Next()
		if c.Writer.Status() >= http.StatusBadRequest {
			return
		}
		route := utils.RouteKey(c)
		alerts.Resolve(c.Request.Context(), databaseAlertKeyPrefix+route,
			"Database request path recovered", "Requests to "+route+" succeed again.")
		alerts.Resolve(c.Request.Context(), internalAlertKeyPrefix+route,
			"API request path recovered", "Requests to "+route+" succeed again.")
		alerts.Resolve(c.Request.Context(), audioAlertKeyPrefix+route,
			"Audio request path recovered", "Audio processing requests to "+route+" succeed again.")
	}
}

// alertRequestFailure reports an operational request failure when middleware
// installed an alerter in the Gin context.
func alertRequestFailure(c *gin.Context, event notify.Event) {
	value, ok := c.Get(alertContextKey)
	if !ok {
		return
	}
	alerts, ok := value.(notify.Alerter)
	if ok && alerts != nil {
		alerts.Alert(c.Request.Context(), event)
	}
}

func handleQueryShapeError(c *gin.Context, err error) bool {
	var invalid apperrors.FieldError
	if unknownField, ok := errors.AsType[*repository.UnknownFieldError](err); ok {
		invalid = apperrors.FieldError{Field: unknownField.Key, Code: apperrors.CodeUnknownField, Message: unknownField.Error()}
	} else if invalidFilter, ok := errors.AsType[*repository.InvalidFilterError](err); ok {
		invalid = apperrors.FieldError{Field: invalidFilter.Key, Code: invalidFilter.Code, Message: invalidFilter.Reason}
	} else {
		return false
	}
	utils.ProblemQueryValidation(c, "Invalid query parameter", invalid)
	return true
}

func handleAvailabilityError(c *gin.Context, err error) bool {
	if deleted, ok := errors.AsType[*repository.StoryDeletedError](err); ok {
		logError("Story", "deleted", err)
		problem := utils.NewExtendedProblem(http.StatusGone, deleted.Error(), "story.deleted",
			"Restore the story with PATCH {\"deleted_at\":\"\"}, optionally with the fields to update")
		problem.DeletedAt = &deleted.DeletedAt
		utils.SendProblem(c, problem)
		return true
	}

	if rateLimited, ok := errors.AsType[*apperrors.RateLimitedError](err); ok {
		logErrorWithCause(rateLimited.Resource, "rate_limited", err, rateLimited.Unwrap())
		if rateLimited.RetryAfter != "" {
			c.Header("Retry-After", rateLimited.RetryAfter)
		}
		utils.ProblemExtended(
			c,
			http.StatusTooManyRequests,
			rateLimited.Error(),
			strings.ToLower(rateLimited.Resource)+".rate_limited",
			"Retry the request later",
		)
		return true
	}

	if upstream, ok := errors.AsType[*apperrors.UpstreamError](err); ok {
		status := upstream.Status
		if status == 0 {
			status = http.StatusBadGateway
		}
		hint := upstream.Hint
		if hint == "" {
			hint = "Please try again later"
		}
		logErrorWithCause(upstream.Resource, "upstream_failed", err, upstream.Unwrap())
		utils.ProblemExtended(
			c,
			status,
			upstream.Error(),
			strings.ToLower(upstream.Resource)+".upstream_failed",
			hint,
		)
		return true
	}

	if ni, ok := errors.AsType[*apperrors.NotInitializedError](err); ok {
		logErrorWithCause(ni.Resource, "not_initialized", err, ni.Unwrap())
		code := strings.ToLower(ni.Resource) + ".not_initialized"
		if ni.Code != "" {
			code = ni.Code
		}
		utils.ProblemExtended(
			c,
			http.StatusServiceUnavailable,
			ni.Error(),
			code,
			ni.Hint,
		)
		return true
	}

	return false
}

// requireTTSEnabled reports whether TTS is configured, writing a 501 response if not.
func (h *Handlers) requireTTSEnabled(c *gin.Context) bool {
	if h.ttsEnabled {
		return true
	}
	utils.ProblemExtended(
		c,
		http.StatusNotImplemented,
		"Text-to-speech is not configured",
		"tts.not_configured",
		"Set BABBEL_ELEVENLABS_API_KEY to enable TTS",
	)
	return false
}

// logError logs a service error with structured fields for filtering, at the
// level errorLevel picks for errorType.
func logError(resource, errorType string, err error) {
	logErrorWithCause(resource, errorType, err, nil)
}

// logErrorWithCause logs like logError and adds the underlying cause.
func logErrorWithCause(resource, errorType string, err error, cause error) {
	fields := map[string]any{
		"resource":   resource,
		"error_type": errorType,
	}
	if cause != nil {
		fields["cause"] = cause.Error()
	}
	logger.WithFields(fields).Log(context.Background(), errorLevel(errorType), err.Error())
}

// errorLevel classifies a handleServiceError error_type, so that only server
// failures log at Error.
func errorLevel(errorType string) slog.Level {
	switch errorType {
	case "not_found", "duplicate", "has_dependencies", "validation_failed", "conflict", "deleted", "client_canceled":
		// Client errors and disconnects: the response tells the client what
		// to fix, or nobody reads it, and the access log records the status.
		return slog.LevelDebug
	case "rate_limited", "upstream_failed", "no_stories":
		// Operational signals: ElevenLabs quota, credentials or failures, and
		// stations without stories. An operator may need to act, and the
		// services that return these errors send the alerts.
		return slog.LevelWarn
	default:
		// Server failures (database_error, audio_failed, and not_initialized
		// for a missing migration or seed row) and any unclassified type.
		return slog.LevelError
	}
}

// deferCleanup wraps cleanup to log errors:
//
//	defer deferCleanup(cleanup, "audio file")()
func deferCleanup(cleanup func() error, resourceType string) func() {
	return func() {
		if err := cleanup(); err != nil {
			logger.Error("Failed to cleanup resource", "type", resourceType, "error", err)
		}
	}
}

// actorUserID returns the authenticated user to attribute a change to, or nil.
func actorUserID(c *gin.Context) *int64 {
	if id, ok := auth.UserID(c); ok {
		return &id
	}
	return nil
}
