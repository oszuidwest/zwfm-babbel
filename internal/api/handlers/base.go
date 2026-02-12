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

// HandlersDeps contains all dependencies required by the API handlers.
type HandlersDeps struct {
	AudioRepo       repository.AudioRepository
	AudioSvc        *audio.Service
	Config          *config.Config
	BulletinSvc     *services.BulletinService
	StorySvc        *services.StoryService
	StationSvc      *services.StationService
	VoiceSvc        *services.VoiceService
	UserSvc         *services.UserService
	StationVoiceSvc *services.StationVoiceService
	TTSEnabled      bool
}

// Handlers contains all the dependencies needed by the API handlers.
type Handlers struct {
	audioRepo repository.AudioRepository
	audioSvc  *audio.Service
	config    *config.Config
	// Domain services
	bulletinSvc     *services.BulletinService
	storySvc        *services.StoryService
	stationSvc      *services.StationService
	voiceSvc        *services.VoiceService
	userSvc         *services.UserService
	stationVoiceSvc *services.StationVoiceService
	ttsEnabled      bool
}

// NewHandlers creates a new Handlers instance with all required dependencies.
func NewHandlers(deps HandlersDeps) *Handlers {
	return &Handlers{
		audioRepo:       deps.AudioRepo,
		audioSvc:        deps.AudioSvc,
		config:          deps.Config,
		bulletinSvc:     deps.BulletinSvc,
		storySvc:        deps.StorySvc,
		stationSvc:      deps.StationSvc,
		voiceSvc:        deps.VoiceSvc,
		userSvc:         deps.UserSvc,
		stationVoiceSvc: deps.StationVoiceSvc,
		ttsEnabled:      deps.TTSEnabled,
	}
}

// handleServiceError maps domain errors to RFC 9457 Problem Details responses.
// Uses errors.AsType for type-safe, generic error matching.
func handleServiceError(c *gin.Context, err error, fallbackResource string) {
	// Context timeout (check first as it's a special case)
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Error("Request timeout: %v", err)
		utils.ProblemExtended(c, http.StatusGatewayTimeout,
			fmt.Sprintf("%s operation timed out", fallbackResource),
			"internal.timeout",
			"The request took too long. Please try again.",
		)
	} else if notFound, ok := errors.AsType[*apperrors.NotFoundError](err); ok {
		logError(notFound.Resource, "not_found", err)
		utils.ProblemExtended(c, http.StatusNotFound,
			notFound.Error(),
			strings.ToLower(notFound.Resource)+".not_found",
			"Check that the ID exists and you have access",
		)
	} else if duplicate, ok := errors.AsType[*apperrors.DuplicateError](err); ok {
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
	} else if dependency, ok := errors.AsType[*apperrors.DependencyError](err); ok {
		logError(dependency.Resource, "has_dependencies", err)
		utils.ProblemExtended(c, http.StatusConflict,
			dependency.Error(),
			strings.ToLower(dependency.Resource)+".has_dependencies",
			fmt.Sprintf("Delete or reassign the associated %s first", dependency.Dependency),
		)
	} else if validation, ok := errors.AsType[*apperrors.ValidationError](err); ok {
		logError(validation.Resource, "validation_failed", err)
		hint := "Check your input and try again"
		if validation.Field != "" {
			hint = fmt.Sprintf("Check the %s field", validation.Field)
		}
		utils.ProblemExtended(c, http.StatusBadRequest,
			validation.Error(),
			strings.ToLower(validation.Resource)+".validation_failed",
			hint,
		)
	} else if noStories, ok := errors.AsType[*apperrors.NoStoriesError](err); ok {
		logError("bulletin", "no_stories", err)
		utils.ProblemExtended(c, http.StatusUnprocessableEntity,
			noStories.Error(),
			"bulletin.no_stories",
			"Add active stories with audio before generating a bulletin",
		)
	} else if audioError, ok := errors.AsType[*apperrors.AudioError](err); ok {
		logErrorWithCause(audioError.Resource, "audio_failed", err, audioError.Unwrap())
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"Audio processing failed",
			"audio.processing_failed",
			"Check the audio file format and try again",
		)
	} else if dbError, ok := errors.AsType[*apperrors.DatabaseError](err); ok {
		logErrorWithCause(dbError.Resource, "database_error", err, dbError.Unwrap())
		utils.ProblemExtended(c, http.StatusInternalServerError,
			"An internal error occurred",
			"internal.database_error",
			"Please try again later",
		)
	} else {
		logger.Error("Unhandled error for %s: %v", fallbackResource, err)
		utils.ProblemExtended(c, http.StatusInternalServerError,
			fmt.Sprintf("Failed to process %s", fallbackResource),
			"internal.unknown_error",
			"Please try again later or contact support",
		)
	}
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
			logger.Error("Failed to cleanup %s: %v", resourceType, err)
		}
	}
}

// convertToListQuery converts utils.QueryParams to repository.ListQuery.
// Delegates to utils.QueryParamsToListQuery to avoid code duplication.
func convertToListQuery(params *utils.QueryParams) *repository.ListQuery {
	return utils.QueryParamsToListQuery(params)
}

// filterFields filters struct fields based on requested field names.
func filterFields[T any](data []T, fields []string) any {
	return utils.FilterStructFields(data, fields)
}

// paramsToListQuery converts utils.QueryParams to repository.ListQuery.
func (h *Handlers) paramsToListQuery(params *utils.QueryParams) *repository.ListQuery {
	return convertToListQuery(params)
}
