// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// HandlersDeps groups dependencies resolved during router setup.
type HandlersDeps struct {
	AudioRepo             repository.AudioRepository
	AudioSvc              *audio.Service
	Config                *config.Config
	BulletinSvc           *services.BulletinService
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
	audioRepo repository.AudioRepository
	audioSvc  *audio.Service
	config    *config.Config
	// Domain services are injected by NewHandlers.
	bulletinSvc           *services.BulletinService
	storySvc              *services.StoryService
	stationSvc            *services.StationService
	voiceSvc              *services.VoiceService
	userSvc               *services.UserService
	stationVoiceSvc       *services.StationVoiceService
	ttsSettingsSvc        *services.TTSSettingsService
	pronunciationRulesSvc *services.PronunciationRulesService
	ttsEnabled            bool
}

// NewHandlers creates endpoint handlers from resolved dependencies.
func NewHandlers(deps HandlersDeps) *Handlers {
	return &Handlers{
		audioRepo:             deps.AudioRepo,
		audioSvc:              deps.AudioSvc,
		config:                deps.Config,
		bulletinSvc:           deps.BulletinSvc,
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
// Uses type-safe error checking with errors.AsType for concrete error types.
func handleServiceError(c *gin.Context, err error, fallbackResource string) {
	// Context timeout (check first as it's a special case)
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Error("Request timeout", "error", err)
		utils.ProblemExtended(c, http.StatusGatewayTimeout,
			fmt.Sprintf("%s operation timed out", fallbackResource),
			"internal.timeout",
			"The request took too long. Please try again.",
		)
		return
	}

	if handleQueryShapeError(c, err, fallbackResource) {
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
		logError(duplicate.Resource, "duplicate", err)
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
		logError(dependency.Resource, "has_dependencies", err)
		utils.ProblemExtended(c, http.StatusConflict,
			dependency.Error(),
			strings.ToLower(dependency.Resource)+".has_dependencies",
			fmt.Sprintf("Delete or reassign the associated %s first", dependency.Dependency),
		)
		return
	}

	if handleConflictError(c, err) {
		return
	}

	if vp, ok := errors.AsType[*apperrors.ValidationProblemError](err); ok {
		logErrorWithCause(strings.ToLower(vp.Resource), "validation_failed", err, vp.Unwrap())
		utils.ProblemValidationError(c, vp.Detail, vp.Errors)
		return
	}

	if validation, ok := errors.AsType[*apperrors.ValidationError](err); ok {
		logErrorWithCause(validation.Resource, "validation_failed", err, validation.Unwrap())
		hint := "Check your input and try again"
		if validation.Field != "" {
			hint = fmt.Sprintf("Check the %s field", validation.Field)
		}
		utils.ProblemExtended(c, http.StatusBadRequest,
			validation.Error(),
			strings.ToLower(validation.Resource)+".validation_failed",
			hint,
		)
		return
	}

	if handleAvailabilityError(c, err) {
		return
	}

	if noStories, ok := errors.AsType[*apperrors.NoStoriesError](err); ok {
		logError("bulletin", "no_stories", err)
		utils.ProblemExtended(c, http.StatusUnprocessableEntity,
			noStories.Error(),
			"bulletin.no_stories",
			"Add active stories with audio before generating a bulletin",
		)
		return
	}

	if audioError, ok := errors.AsType[*apperrors.AudioError](err); ok {
		logErrorWithCause(audioError.Resource, "audio_failed", err, audioError.Unwrap())
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"Audio processing failed",
			"audio.processing_failed",
			"Check the audio file format and try again",
		)
		return
	}

	if dbError, ok := errors.AsType[*apperrors.DatabaseError](err); ok {
		logErrorWithCause(dbError.Resource, "database_error", err, dbError.Unwrap())
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"An internal error occurred",
			"internal.database_error",
			"Please try again later",
		)
		return
	}

	// Unknown errors fall back to a generic internal problem response.
	logger.Error("Unhandled error", "resource", fallbackResource, "error", err)
	utils.ProblemExtended(c, http.StatusInternalServerError,
		fmt.Sprintf("Failed to process %s", fallbackResource),
		"internal.unknown_error",
		"Please try again later or contact support",
	)
}

func handleQueryShapeError(c *gin.Context, err error, fallbackResource string) bool {
	var unknownField *repository.UnknownFieldError
	if errors.As(err, &unknownField) {
		logError(strings.ToLower(fallbackResource), "unknown_query_field", err)
		utils.ProblemValidationError(c, "Invalid query parameter", []apperrors.ValidationError{
			{Field: unknownField.Kind, Message: unknownField.Error()},
		})
		return true
	}

	var invalidFilter *repository.InvalidFilterError
	if errors.As(err, &invalidFilter) {
		logError(strings.ToLower(fallbackResource), "invalid_filter", err)
		utils.ProblemValidationError(c, "Invalid query parameter", []apperrors.ValidationError{
			{Field: fmt.Sprintf("filter[%s][%s]", invalidFilter.Field, invalidFilter.Operator), Message: invalidFilter.Reason},
		})
		return true
	}

	return false
}

func handleConflictError(c *gin.Context, err error) bool {
	if conflict, ok := errors.AsType[*apperrors.ConflictError](err); ok {
		logErrorWithCause(conflict.Resource, "conflict", err, conflict.Unwrap())
		code := strings.ToLower(conflict.Resource) + ".conflict"
		if conflict.Code != "" {
			code = conflict.Code
		}
		hint := conflict.Hint
		if hint == "" {
			hint = "Reload the resource and try again"
		}
		utils.ProblemExtended(c, http.StatusConflict, conflict.Error(), code, hint)
		return true
	}

	return false
}

func handleAvailabilityError(c *gin.Context, err error) bool {
	if rateLimited, ok := errors.AsType[*apperrors.RateLimitedError](err); ok {
		logError(rateLimited.Resource, "rate_limited", err)
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
		logError(ni.Resource, "not_initialized", err)
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

// requireTTSEnabled writes a 501 Problem response when TTS is not configured
// and returns false. Used by every endpoint that depends on the ElevenLabs API.
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

// logError logs an error with structured fields for filtering.
func logError(resource, errorType string, err error) {
	logger.WithFields(map[string]any{
		"resource":   resource,
		"error_type": errorType,
	}).Error(err.Error())
}

// logErrorWithCause logs an error with the underlying cause for internal errors.
func logErrorWithCause(resource, errorType string, err error, cause error) {
	fields := map[string]any{
		"resource":   resource,
		"error_type": errorType,
	}
	if cause != nil {
		fields["cause"] = cause.Error()
	}
	logger.WithFields(fields).Error(err.Error())
}

// deferCleanup returns a function suitable for use with defer that logs cleanup errors.
// Usage: defer deferCleanup(cleanup, "audio file")().
func deferCleanup(cleanup func() error, resourceType string) func() {
	return func() {
		if err := cleanup(); err != nil {
			logger.Error("Failed to cleanup resource", "type", resourceType, "error", err)
		}
	}
}
