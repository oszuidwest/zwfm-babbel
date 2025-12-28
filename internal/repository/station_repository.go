// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
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

	err := r.GormRepository.db.WithContext(ctx).Create(station).Error
	if err != nil {
		if IsDuplicateKeyError(err) {
			return nil, ErrDuplicateKey
		}
		return nil, err
	}

	return station, nil
}

// GetByID retrieves a station by its ID.
func (r *stationRepository) GetByID(ctx context.Context, id int64) (*models.Station, error) {
	return r.GormRepository.GetByID(ctx, id)
}

// Update updates an existing station with type-safe fields.
func (r *stationRepository) Update(ctx context.Context, id int64, updates *StationUpdate) error {
	if updates == nil {
		return nil
	}

	// Build the update map with only non-nil fields
	updateMap := make(map[string]any)

	if updates.Name != nil {
		updateMap["name"] = *updates.Name
	}
	if updates.MaxStoriesPerBlock != nil {
		updateMap["max_stories_per_block"] = *updates.MaxStoriesPerBlock
	}
	if updates.PauseSeconds != nil {
		updateMap["pause_seconds"] = *updates.PauseSeconds
	}

	if len(updateMap) == 0 {
		return nil
	}

	result := r.GormRepository.db.WithContext(ctx).
		Model(&models.Station{}).
		Where("id = ?", id).
		Updates(updateMap)

	if result.Error != nil {
		if IsDuplicateKeyError(result.Error) {
			return ErrDuplicateKey
		}
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete removes a station by its ID.
func (r *stationRepository) Delete(ctx context.Context, id int64) error {
	return r.GormRepository.Delete(ctx, id)
}

// Exists checks if a station with the given ID exists.
func (r *stationRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// IsNameTaken checks if a station name is already in use.
func (r *stationRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	var count int64
	query := r.GormRepository.db.WithContext(ctx).
		Model(&models.Station{}).
		Where("name = ?", name)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	err := query.Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// HasDependencies checks if station has any station_voices relationships.
func (r *stationRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	var count int64
	err := r.GormRepository.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("station_id = ?", id).
		Count(&count).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	return count > 0, nil
}
