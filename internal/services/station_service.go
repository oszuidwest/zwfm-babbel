// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// StationService handles station-related business logic.
type StationService struct {
	repo repository.StationRepository
}

// NewStationService creates a new station service instance.
func NewStationService(repo repository.StationRepository) *StationService {
	return &StationService{
		repo: repo,
	}
}

// UpdateStationRequest contains the data needed to update an existing station.
type UpdateStationRequest struct {
	Name               *string  `json:"name"`
	MaxStoriesPerBlock *int     `json:"max_stories_per_block"`
	PauseSeconds       *float64 `json:"pause_seconds"`
}

// Create creates a new station with the given parameters.
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

// Update updates an existing station's configuration and returns the updated station.
func (s *StationService) Update(ctx context.Context, id int64, req *UpdateStationRequest) (*models.Station, error) {
	const op = "StationService.Update"

	// Check name uniqueness if name is being updated
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
		}
		if taken {
			return nil, fmt.Errorf("%s: %w: station name '%s'", op, apperrors.ErrDuplicate, *req.Name)
		}
	}

	// Build type-safe update struct
	updates := &repository.StationUpdate{
		Name:               req.Name,
		MaxStoriesPerBlock: req.MaxStoriesPerBlock,
		PauseSeconds:       req.PauseSeconds,
	}

	// Update station
	if err := s.repo.Update(ctx, id, updates); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return s.GetByID(ctx, id)
}

// Exists reports whether a station with the given ID exists.
func (s *StationService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return false, fmt.Errorf("%w: failed to check station existence: %v", apperrors.ErrDatabaseError, err)
	}
	return exists, nil
}

// Delete deletes a station after checking for dependencies.
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

// GetByID retrieves a station by ID.
func (s *StationService) GetByID(ctx context.Context, id int64) (*models.Station, error) {
	const op = "StationService.GetByID"

	station, err := s.repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return station, nil
}

// List returns a paginated list of stations.
func (s *StationService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Station], error) {
	const op = "StationService.List"

	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return result, nil
}
