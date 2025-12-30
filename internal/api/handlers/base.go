// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"context"
	"errors"
	"fmt"

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
	}
}

// handleServiceError maps domain errors to RFC 9457 Problem Details responses.
func handleServiceError(c *gin.Context, err error, resource string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		logger.Error("Request timeout for %s: %v", resource, err)
		utils.ProblemInternalServer(c, fmt.Sprintf("%s operation timed out", resource))
	case errors.Is(err, apperrors.ErrNotFound):
		utils.ProblemNotFound(c, resource)
	case errors.Is(err, apperrors.ErrDuplicate):
		utils.ProblemDuplicate(c, resource)
	case errors.Is(err, apperrors.ErrDependencyExists):
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, fmt.Sprintf("Cannot delete %s: it has dependencies", resource))
	case errors.Is(err, apperrors.ErrInvalidInput):
		utils.ProblemBadRequest(c, extractErrorMessage(err))
	case errors.Is(err, apperrors.ErrDataTooLong):
		utils.ProblemCustom(c, "https://babbel.api/problems/data-too-long", "Data Too Long", 422, extractErrorMessage(err))
	case errors.Is(err, apperrors.ErrNoStoriesAvailable):
		utils.ProblemCustom(c, "https://babbel.api/problems/no-stories", "No Stories Available", 422, "No active stories available")
	case errors.Is(err, apperrors.ErrAudioProcessingFailed):
		logger.Error("Audio processing failed: %v", err)
		utils.ProblemInternalServer(c, "Audio processing failed")
	case errors.Is(err, apperrors.ErrDatabaseError):
		logger.Error("Database error: %v", err)
		utils.ProblemInternalServer(c, "Internal error")
	default:
		logger.Error("Unhandled error for %s: %v", resource, err)
		utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
	}
}

// extractErrorMessage extracts a user-safe message from wrapped errors.
func extractErrorMessage(err error) string {
	if err == nil {
		return "Invalid input"
	}
	msg := err.Error()
	// The error message format is typically "context: sentinel: details"
	// We want to show meaningful details to the user
	return msg
}

// deferCleanup returns a function suitable for use with defer that logs cleanup errors.
// Usage: defer deferCleanup(cleanup, "audio file")()
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
