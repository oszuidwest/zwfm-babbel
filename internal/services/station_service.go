// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// StationService handles station-related business logic
type StationService struct {
	repo repository.StationRepository
}

// NewStationService creates a new station service instance
func NewStationService(repo repository.StationRepository) *StationService {
	return &StationService{
		repo: repo,
	}
}

// Create creates a new station with the given parameters
func (s *StationService) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	const op = "StationService.Create"

	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: station name '%s'", op, ErrDuplicate, name)
	}

	// Create station
	station, err := s.repo.Create(ctx, name, maxStories, pauseSeconds)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: station name '%s'", op, ErrDuplicate, name)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return station, nil
}

// Update updates an existing station's configuration
func (s *StationService) Update(ctx context.Context, id int, name string, maxStories int, pauseSeconds float64) error {
	const op = "StationService.Update"

	// Check if station exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Check name uniqueness (excluding current record)
	taken, err := s.repo.IsNameTaken(ctx, name, &id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%s: %w: station name '%s'", op, ErrDuplicate, name)
	}

	// Update station
	err = s.repo.Update(ctx, id, name, maxStories, pauseSeconds)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// Delete deletes a station after checking for dependencies
func (s *StationService) Delete(ctx context.Context, id int) error {
	const op = "StationService.Delete"

	// Check if station exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: station has associated voices", op, ErrDependencyExists)
	}

	// Delete station
	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// DB returns the underlying database for ModernListWithQuery.
func (s *StationService) DB() *sqlx.DB {
	return s.repo.DB()
}
