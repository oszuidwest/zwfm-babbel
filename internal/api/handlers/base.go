// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"errors"
	"fmt"
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
// Using a struct for dependencies improves readability and makes adding new
// dependencies easier without changing function signatures.
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
// Internal error details are logged but never exposed to clients.
func handleServiceError(c *gin.Context, err error, resource string) {
	switch {
	case errors.Is(err, apperrors.ErrNotFound):
		utils.ProblemNotFound(c, resource)
	case errors.Is(err, apperrors.ErrDuplicate):
		utils.ProblemDuplicate(c, resource)
	case errors.Is(err, apperrors.ErrDependencyExists):
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, fmt.Sprintf("Cannot delete %s: it has dependencies", resource))
	case errors.Is(err, apperrors.ErrInvalidInput):
		utils.ProblemBadRequest(c, extractErrorMessage(err))
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
// For errors wrapped with fmt.Errorf("%w: message", err), it returns the message portion.
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
// This is used by handlers that need to pass query parameters to service layer.
func convertToListQuery(params *utils.QueryParams) *repository.ListQuery {
	if params == nil {
		return repository.NewListQuery()
	}

	query := &repository.ListQuery{
		Limit:  params.Limit,
		Offset: params.Offset,
		Search: params.Search,
		Status: params.Status,
	}

	// Convert sort fields
	for _, sf := range params.Sort {
		direction := repository.SortAsc
		if strings.ToLower(sf.Direction) == "desc" {
			direction = repository.SortDesc
		}
		query.Sort = append(query.Sort, repository.SortField{
			Field:     sf.Field,
			Direction: direction,
		})
	}

	// Convert filters
	for field, filter := range params.Filters {
		condition := repository.FilterCondition{
			Field: field,
			Value: filter.Value,
		}

		// Map operator strings to repository.FilterOperator
		switch filter.Operator {
		case "=":
			condition.Operator = repository.FilterEquals
		case "!=":
			condition.Operator = repository.FilterNotEquals
		case ">":
			condition.Operator = repository.FilterGreaterThan
		case ">=":
			condition.Operator = repository.FilterGreaterOrEq
		case "<":
			condition.Operator = repository.FilterLessThan
		case "<=":
			condition.Operator = repository.FilterLessOrEq
		case "LIKE":
			condition.Operator = repository.FilterLike
		case "IN":
			condition.Operator = repository.FilterIn
			condition.Value = filter.Values
		default:
			condition.Operator = repository.FilterEquals
		}

		query.Filters = append(query.Filters, condition)
	}

	return query
}

// filterFields filters struct fields based on requested field names.
// Used for sparse fieldsets in list responses.
func filterFields[T any](data []T, fields []string) any {
	return utils.FilterStructFields(data, fields)
}

// paramsToListQuery converts utils.QueryParams to repository.ListQuery.
// This is a method version for use by handlers.
func (h *Handlers) paramsToListQuery(params *utils.QueryParams) *repository.ListQuery {
	return convertToListQuery(params)
}
