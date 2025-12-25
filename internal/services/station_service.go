// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// StationService handles station-related business logic
type StationService struct {
	db *sqlx.DB
}

// NewStationService creates a new station service instance
func NewStationService(db *sqlx.DB) *StationService {
	return &StationService{
		db: db,
	}
}

// Create creates a new station with the given parameters
func (s *StationService) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	const op = "StationService.Create"

	// Check name uniqueness
	if err := s.CheckNameUnique(ctx, name, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Create station
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		name, maxStories, pauseSeconds,
	)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get last insert id: %w", op, err)
	}

	// Fetch the created station
	station, err := s.GetByID(ctx, int(id))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return station, nil
}

// Update updates an existing station's configuration
func (s *StationService) Update(ctx context.Context, id int, name string, maxStories int, pauseSeconds float64) error {
	const op = "StationService.Update"

	// Check if station exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Check name uniqueness (excluding current record)
	if err := s.CheckNameUnique(ctx, name, &id); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Update station
	result, err := s.db.ExecContext(ctx,
		"UPDATE stations SET name = ?, max_stories_per_block = ?, pause_seconds = ? WHERE id = ?",
		name, maxStories, pauseSeconds, id,
	)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// GetByID retrieves a station by its ID
func (s *StationService) GetByID(ctx context.Context, id int) (*models.Station, error) {
	const op = "StationService.GetByID"

	var station models.Station
	err := s.db.GetContext(ctx, &station, "SELECT * FROM stations WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return &station, nil
}

// Delete deletes a station after checking for dependencies
func (s *StationService) Delete(ctx context.Context, id int) error {
	const op = "StationService.Delete"

	// Check if station exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Check for dependencies
	hasDeps, err := s.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: station has associated voices", op, ErrDependencyExists)
	}

	// Delete station
	result, err := s.db.ExecContext(ctx, "DELETE FROM stations WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// CheckNameUnique checks if a station name is unique
// excludeID can be provided to exclude a specific station from the check (for updates)
func (s *StationService) CheckNameUnique(ctx context.Context, name string, excludeID *int) error {
	const op = "StationService.CheckNameUnique"

	var count int
	query := "SELECT COUNT(*) FROM stations WHERE name = ?"
	args := []interface{}{name}

	if excludeID != nil {
		query += " AND id != ?"
		args = append(args, *excludeID)
	}

	err := s.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	if count > 0 {
		return fmt.Errorf("%s: %w: station name '%s'", op, ErrDuplicate, name)
	}

	return nil
}

// HasDependencies checks if a station has any dependencies (station_voices)
func (s *StationService) HasDependencies(ctx context.Context, id int) (bool, error) {
	const op = "StationService.HasDependencies"

	var count int
	err := s.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ?", id)
	if err != nil {
		return false, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return count > 0, nil
}
