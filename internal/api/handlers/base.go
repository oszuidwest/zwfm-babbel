// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
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

// handleServiceError converts service layer errors to appropriate HTTP responses
func handleServiceError(c *gin.Context, err error, resource string) {
	switch {
	case errors.Is(err, services.ErrNotFound):
		utils.ProblemNotFound(c, resource)
	case errors.Is(err, services.ErrDuplicate):
		utils.ProblemDuplicate(c, resource)
	case errors.Is(err, services.ErrDependencyExists):
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, fmt.Sprintf("Cannot delete %s: it has dependencies", resource))
	case errors.Is(err, services.ErrInvalidInput):
		utils.ProblemBadRequest(c, err.Error())
	default:
		utils.ProblemInternalServer(c, fmt.Sprintf("Failed to process %s", resource))
	}
}
