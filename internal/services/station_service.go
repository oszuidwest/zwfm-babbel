// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

// StationService handles station-related business logic
type StationService struct {
	repo   repository.StationRepository
	gormDB *gorm.DB
}

// NewStationService creates a new station service instance
func NewStationService(repo repository.StationRepository, gormDB *gorm.DB) *StationService {
	return &StationService{
		repo:   repo,
		gormDB: gormDB,
	}
}

// UpdateStationRequest contains the data needed to update an existing station.
type UpdateStationRequest struct {
	Name               *string  `json:"name"`
	MaxStoriesPerBlock *int     `json:"max_stories_per_block"`
	PauseSeconds       *float64 `json:"pause_seconds"`
}

// Create creates a new station with the given parameters
func (s *StationService) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	const op = "StationService.Create"

	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: station name '%s'", op, apperrors.ErrDuplicate, name)
	}

	// Create station
	station, err := s.repo.Create(ctx, name, maxStories, pauseSeconds)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: station name '%s'", op, apperrors.ErrDuplicate, name)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return station, nil
}

// Update updates an existing station's configuration
func (s *StationService) Update(ctx context.Context, id int64, req *UpdateStationRequest) error {
	const op = "StationService.Update"

	// Check if station exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	// Check name uniqueness if name is being updated
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
		}
		if taken {
			return fmt.Errorf("%s: %w: station name '%s'", op, apperrors.ErrDuplicate, *req.Name)
		}
	}

	// Build type-safe update struct
	updates := &repository.StationUpdate{
		Name:               req.Name,
		MaxStoriesPerBlock: req.MaxStoriesPerBlock,
		PauseSeconds:       req.PauseSeconds,
	}

	// Update station
	err = s.repo.Update(ctx, id, updates)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return nil
}

// Delete deletes a station after checking for dependencies
func (s *StationService) Delete(ctx context.Context, id int64) error {
	const op = "StationService.Delete"

	// Check if station exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: station has associated voices", op, apperrors.ErrDependencyExists)
	}

	// Delete station
	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return nil
}

// GetByIDWithContext retrieves a station by ID and writes the JSON response.
func (s *StationService) GetByIDWithContext(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	station, err := s.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			utils.ProblemNotFound(c, "Station")
			return
		}
		utils.ProblemInternalServer(c, "Failed to retrieve station")
		return
	}

	c.JSON(200, station)
}

// ListWithContext handles paginated list requests with query parameters.
// Encapsulates query configuration and writes JSON response directly.
func (s *StationService) ListWithContext(c *gin.Context) {
	config := utils.GormListConfig{
		SearchFields: []string{"name"},
		FieldMapping: map[string]string{
			"id":                    "id",
			"name":                  "name",
			"max_stories_per_block": "max_stories_per_block",
			"pause_seconds":         "pause_seconds",
			"created_at":            "created_at",
			"updated_at":            "updated_at",
		},
		DefaultSort: "name ASC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.Station](c, s.gormDB, config)
}
