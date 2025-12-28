// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository/updates"
	"gorm.io/gorm"
)

// StationUpdate contains optional fields for updating a station.
// Nil pointer fields are not updated.
type StationUpdate struct {
	Name               *string  `db:"name"`
	MaxStoriesPerBlock *int     `db:"max_stories_per_block"`
	PauseSeconds       *float64 `db:"pause_seconds"`
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
func (r *stationRepository) Update(ctx context.Context, id int64, u *StationUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := updates.ToMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.Station{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return ParseDBError(result.Error)
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

// List retrieves a paginated list of stations with filtering, sorting, and search.
func (r *stationRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Station], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Field mapping for stations (API field name -> DB column)
	fieldMapping := map[string]string{
		"id":                    "id",
		"name":                  "name",
		"max_stories_per_block": "max_stories_per_block",
		"pause_seconds":         "pause_seconds",
		"created_at":            "created_at",
		"updated_at":            "updated_at",
	}

	// Search fields for stations
	searchFields := []string{"name"}

	// Build base query
	baseQuery := r.db.WithContext(ctx).Model(&models.Station{})

	// Apply search
	if query.Search != "" {
		searchPattern := "%" + query.Search + "%"
		baseQuery = baseQuery.Where("name LIKE ?", searchPattern)
	}

	// Apply filters using the shared applyFilterWithMapping helper
	for _, filter := range query.Filters {
		baseQuery = applyFilterWithMapping(baseQuery, filter, fieldMapping)
	}

	// Count total before pagination
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sf := range query.Sort {
			dbField, ok := fieldMapping[sf.Field]
			if !ok {
				continue
			}
			direction := "ASC"
			if sf.Direction == SortDesc {
				direction = "DESC"
			}
			baseQuery = baseQuery.Order(dbField + " " + direction)
		}
	} else {
		// Default sort by name
		baseQuery = baseQuery.Order("name ASC")
	}

	// Apply pagination
	baseQuery = baseQuery.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var stations []models.Station
	if err := baseQuery.Find(&stations).Error; err != nil {
		return nil, err
	}

	// Suppress unused variable warning for searchFields
	_ = searchFields

	return &ListResult[models.Station]{
		Data:   stations,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
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
