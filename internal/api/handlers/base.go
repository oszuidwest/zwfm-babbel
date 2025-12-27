// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
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
func NewHandlers(
	audioRepo repository.AudioRepository,
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
		audioRepo:       audioRepo,
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

// errorCodeHandler defines a function that handles a specific error code.
type errorCodeHandler func(c *gin.Context, resource string, appErr *apperrors.Error)

// errorCodeHandlers maps error codes to their corresponding HTTP response handlers.
var errorCodeHandlers = map[apperrors.Code]errorCodeHandler{
	apperrors.CodeNotFound: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemNotFound(c, resource)
	},
	apperrors.CodeDuplicate: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemDuplicate(c, resource)
	},
	apperrors.CodeDependencyExists: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, appErr.Message)
	},
	apperrors.CodeInvalidInput: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemBadRequest(c, appErr.Message)
	},
	apperrors.CodeValidation: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemBadRequest(c, appErr.Message)
	},
	apperrors.CodeNoStoriesAvailable: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemCustom(c, "https://babbel.api/problems/no-stories", "No Stories Available", 422, appErr.Message)
	},
	apperrors.CodeAudioProcessing: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemInternalServer(c, appErr.Message)
	},
	apperrors.CodeUnauthorized: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemUnauthorized(c, appErr.Message)
	},
	apperrors.CodeForbidden: func(c *gin.Context, resource string, appErr *apperrors.Error) {
		utils.ProblemForbidden(c, appErr.Message)
	},
}

// legacyErrorHandler defines a function that checks and handles legacy sentinel errors.
type legacyErrorHandler func(c *gin.Context, err error, resource string) bool

// legacyErrorHandlers contains handlers for backwards-compatible sentinel errors.
var legacyErrorHandlers = []legacyErrorHandler{
	func(c *gin.Context, err error, resource string) bool {
		if errors.Is(err, services.ErrNotFound) {
			utils.ProblemNotFound(c, resource)
			return true
		}
		return false
	},
	func(c *gin.Context, err error, resource string) bool {
		if errors.Is(err, services.ErrDuplicate) {
			utils.ProblemDuplicate(c, resource)
			return true
		}
		return false
	},
	func(c *gin.Context, err error, resource string) bool {
		if errors.Is(err, services.ErrDependencyExists) {
			utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, fmt.Sprintf("Cannot delete %s: it has dependencies", resource))
			return true
		}
		return false
	},
	func(c *gin.Context, err error, resource string) bool {
		if errors.Is(err, services.ErrInvalidInput) {
			utils.ProblemBadRequest(c, "Invalid input data")
			return true
		}
		return false
	},
	func(c *gin.Context, err error, resource string) bool {
		if errors.Is(err, services.ErrNoStoriesAvailable) {
			utils.ProblemCustom(c, "https://babbel.api/problems/no-stories", "No Stories Available", 422, "No active stories available")
			return true
		}
		return false
	},
}

// logAppErrorDetails logs internal error details without exposing them to clients.
func logAppErrorDetails(appErr *apperrors.Error, resource string) {
	if appErr.Internal != "" {
		logger.Error("%s error: %s (internal: %s)", resource, appErr.Message, appErr.Internal)
	}
	if appErr.Err != nil {
		logger.Error("%s underlying error: %v", resource, appErr.Err)
	}
}

// handleAppError processes an apperrors.Error and returns the appropriate HTTP response.
func handleAppError(c *gin.Context, appErr *apperrors.Error, resource string) {
	logAppErrorDetails(appErr, resource)

	if handler, exists := errorCodeHandlers[appErr.Code]; exists {
		handler(c, resource, appErr)
		return
	}

	utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
}

// handleLegacyError checks for legacy sentinel errors and handles them appropriately.
// Returns true if a legacy error was handled, false otherwise.
func handleLegacyError(c *gin.Context, err error, resource string) bool {
	for _, handler := range legacyErrorHandlers {
		if handler(c, err, resource) {
			return true
		}
	}
	return false
}

// handleServiceError converts apperrors.Error to appropriate HTTP responses.
// Internal error details are logged but never exposed to clients.
func handleServiceError(c *gin.Context, err error, resource string) {
	var appErr *apperrors.Error
	if errors.As(err, &appErr) {
		handleAppError(c, appErr, resource)
		return
	}

	if handleLegacyError(c, err, resource) {
		return
	}

	logger.Error("Unhandled error for %s: %v", resource, err)
	utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
}
