// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// StationUpdate contains optional fields for updating a station.
// Nil pointer fields are not updated.
type StationUpdate struct {
	Name               *string  `gorm:"column:name"`
	MaxStoriesPerBlock *int     `gorm:"column:max_stories_per_block"`
	PauseSeconds       *float64 `gorm:"column:pause_seconds"`
}

// hasUpdates returns true if any update field is non-nil.
func (u *StationUpdate) hasUpdates() bool {
	return u.Name != nil || u.MaxStoriesPerBlock != nil || u.PauseSeconds != nil
}

// StationRepository defines the interface for station data access.
type StationRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error)
	GetByID(ctx context.Context, id int64) (*models.Station, error)
	Update(ctx context.Context, id int64, updates *StationUpdate) error
	Delete(ctx context.Context, id int64) error

	// Query operations
	List(ctx context.Context, query *ListQuery) (*ListResult[models.Station], error)
	Exists(ctx context.Context, id int64) (bool, error)
	IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error)
	HasDependencies(ctx context.Context, id int64) (bool, error)
}

// stationRepository implements StationRepository using GORM.
type stationRepository struct {
	*GormRepository[models.Station]
}

// NewStationRepository creates a new station repository.
func NewStationRepository(db *gorm.DB) StationRepository {
	return &stationRepository{
		GormRepository: NewGormRepository[models.Station](db),
	}
}

// Create inserts a new station and returns the created record.
func (r *stationRepository) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	station := &models.Station{
		Name:               name,
		MaxStoriesPerBlock: maxStories,
		PauseSeconds:       pauseSeconds,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(station).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return station, nil
}

// GetByID retrieves a station by its ID.
func (r *stationRepository) GetByID(ctx context.Context, id int64) (*models.Station, error) {
	return r.GormRepository.GetByID(ctx, id)
}

// Update updates an existing station with type-safe fields.
func (r *stationRepository) Update(ctx context.Context, id int64, u *StationUpdate) error {
	if u == nil || !u.hasUpdates() {
		return nil
	}
	return r.UpdateByID(ctx, id, u)
}

// Delete removes a station by its ID.
func (r *stationRepository) Delete(ctx context.Context, id int64) error {
	return r.GormRepository.Delete(ctx, id)
}

// stationFieldMapping maps API field names to database columns for stations.
var stationFieldMapping = FieldMapping{
	"id":                    "id",
	"name":                  "name",
	"max_stories_per_block": "max_stories_per_block",
	"pause_seconds":         "pause_seconds",
	"created_at":            "created_at",
	"updated_at":            "updated_at",
}

// stationSearchFields defines which fields are searchable for stations.
var stationSearchFields = []string{"name"}

// List retrieves a paginated list of stations with filtering, sorting, and search.
func (r *stationRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Station], error) {
	db := r.db.WithContext(ctx).Model(&models.Station{})
	return ApplyListQuery[models.Station](db, query, stationFieldMapping, stationSearchFields, "name ASC")
}

// Exists checks if a station with the given ID exists.
func (r *stationRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// IsNameTaken checks if a station name is already in use.
func (r *stationRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "name", name, excludeID)
}

// HasDependencies checks if station has any station_voices relationships.
func (r *stationRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	return r.HasRelatedRecords(ctx, id, map[string]string{
		"station_voices": "station_id",
	})
}
