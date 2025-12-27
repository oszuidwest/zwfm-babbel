// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// StationUpdate contains optional fields for updating a station.
// Nil pointer fields are not updated.
type StationUpdate struct {
	Name               *string
	MaxStoriesPerBlock *int
	PauseSeconds       *float64
}

// StationRepository defines the interface for station data access.
type StationRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error)
	GetByID(ctx context.Context, id int64) (*models.Station, error)
	Update(ctx context.Context, id int64, updates *StationUpdate) error
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

// Update updates an existing station with type-safe fields.
func (r *stationRepository) Update(ctx context.Context, id int64, updates *StationUpdate) error {
	if updates == nil {
		return nil
	}

	q := r.getQueryable(ctx)

	setClauses := make([]string, 0, 3)
	args := make([]any, 0, 3)

	addFieldUpdate(&setClauses, &args, "name", updates.Name)
	addFieldUpdate(&setClauses, &args, "max_stories_per_block", updates.MaxStoriesPerBlock)
	addFieldUpdate(&setClauses, &args, "pause_seconds", updates.PauseSeconds)

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf("UPDATE stations SET %s WHERE id = ?", strings.Join(setClauses, ", "))
	args = append(args, id)

	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return ParseDBError(err)
	}

	return checkRowsAffected(result)
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
