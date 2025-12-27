// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// StationRepository defines the interface for station data access.
type StationRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error)
	GetByID(ctx context.Context, id int64) (*models.Station, error)
	Update(ctx context.Context, id int64, name string, maxStories int, pauseSeconds float64) error
	Delete(ctx context.Context, id int64) error

	// Query operations
	Exists(ctx context.Context, id int64) (bool, error)
	IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error)
	HasDependencies(ctx context.Context, id int64) (bool, error)

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// stationRepository implements StationRepository.
type stationRepository struct {
	*BaseRepository[models.Station]
}

// NewStationRepository creates a new station repository.
func NewStationRepository(db *sqlx.DB) StationRepository {
	return &stationRepository{
		BaseRepository: NewBaseRepository[models.Station](db, "stations"),
	}
}

// Create inserts a new station and returns the created record.
func (r *stationRepository) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		name, maxStories, pauseSeconds,
	)
	if err != nil {
		return nil, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return r.GetByID(ctx, id)
}

// Update updates an existing station's fields.
func (r *stationRepository) Update(ctx context.Context, id int64, name string, maxStories int, pauseSeconds float64) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		"UPDATE stations SET name = ?, max_stories_per_block = ?, pause_seconds = ? WHERE id = ?",
		name, maxStories, pauseSeconds, id,
	)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// IsNameTaken checks if a station name is already in use.
func (r *stationRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	condition := "name = ?"
	args := []any{name}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// HasDependencies checks if station has any station_voices relationships.
func (r *stationRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	q := r.getQueryable(ctx)

	var count int
	err := q.GetContext(ctx, &count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ?", id)
	if err != nil {
		return false, ParseDBError(err)
	}

	return count > 0, nil
}
