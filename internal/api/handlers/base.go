// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// Handlers contains all the dependencies needed by the API handlers.
type Handlers struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
	// New services
	bulletinSvc     *services.BulletinService
	storySvc        *services.StoryService
	stationSvc      *services.StationService
	voiceSvc        *services.VoiceService
	userSvc         *services.UserService
	stationVoiceSvc *services.StationVoiceService
}

// NewHandlers creates a new Handlers instance with all required dependencies.
func NewHandlers(
	db *sqlx.DB,
	audioSvc *audio.Service,
	cfg *config.Config,
	bulletinSvc *services.BulletinService,
	storySvc *services.StoryService,
	stationSvc *services.StationService,
	voiceSvc *services.VoiceService,
	userSvc *services.UserService,
	stationVoiceSvc *services.StationVoiceService,
) *Handlers {
	return &Handlers{
		db:              db,
		audioSvc:        audioSvc,
		config:          cfg,
		bulletinSvc:     bulletinSvc,
		storySvc:        storySvc,
		stationSvc:      stationSvc,
		voiceSvc:        voiceSvc,
		userSvc:         userSvc,
		stationVoiceSvc: stationVoiceSvc,
	}
}

// handleServiceError converts apperrors.Error to appropriate HTTP responses.
// Internal error details are logged but never exposed to clients.
func handleServiceError(c *gin.Context, err error, resource string) {
	var appErr *apperrors.Error
	if errors.As(err, &appErr) {
		// Log internal details if present
		if appErr.Internal != "" {
			logger.Error("%s error: %s (internal: %s)", resource, appErr.Message, appErr.Internal)
		}
		if appErr.Err != nil {
			logger.Error("%s underlying error: %v", resource, appErr.Err)
		}

		// Map error code to HTTP response
		switch appErr.Code {
		case apperrors.CodeNotFound:
			utils.ProblemNotFound(c, resource)
		case apperrors.CodeDuplicate:
			utils.ProblemDuplicate(c, resource)
		case apperrors.CodeDependencyExists:
			utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, appErr.Message)
		case apperrors.CodeInvalidInput, apperrors.CodeValidation:
			utils.ProblemBadRequest(c, appErr.Message)
		case apperrors.CodeNoStoriesAvailable:
			utils.ProblemCustom(c, "https://babbel.api/problems/no-stories", "No Stories Available", 422, appErr.Message)
		case apperrors.CodeAudioProcessing:
			utils.ProblemInternalServer(c, appErr.Message)
		case apperrors.CodeUnauthorized:
			utils.ProblemUnauthorized(c, appErr.Message)
		case apperrors.CodeForbidden:
			utils.ProblemForbidden(c, appErr.Message)
		default:
			utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
		}
		return
	}

	// Fallback: check legacy sentinel errors for backwards compatibility
	switch {
	case errors.Is(err, services.ErrNotFound):
		utils.ProblemNotFound(c, resource)
	case errors.Is(err, services.ErrDuplicate):
		utils.ProblemDuplicate(c, resource)
	case errors.Is(err, services.ErrDependencyExists):
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, fmt.Sprintf("Cannot delete %s: it has dependencies", resource))
	case errors.Is(err, services.ErrInvalidInput):
		utils.ProblemBadRequest(c, "Invalid input data")
	case errors.Is(err, services.ErrNoStoriesAvailable):
		utils.ProblemCustom(c, "https://babbel.api/problems/no-stories", "No Stories Available", 422, "No active stories available")
	default:
		logger.Error("Unhandled error for %s: %v", resource, err)
		utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
	}
}
