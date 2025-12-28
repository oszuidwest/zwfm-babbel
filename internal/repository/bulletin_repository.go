// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// BulletinRepository defines the interface for bulletin data access.
type BulletinRepository interface {
	// CRUD operations
	Create(ctx context.Context, stationID int64, filename, audioFile string, duration float64, fileSize int64, storyCount int) (int64, error)
	GetByID(ctx context.Context, id int64) (*models.Bulletin, error)

	// Query operations
	GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error)

	// Story linking
	LinkStories(ctx context.Context, bulletinID int64, storyIDs []int64) error

	// GormDB returns the underlying GORM database for complex queries
	GormDB() *gorm.DB
}

// bulletinRepository implements BulletinRepository using GORM.
type bulletinRepository struct {
	*GormRepository[models.Bulletin]
}

// NewBulletinRepository creates a new bulletin repository.
func NewBulletinRepository(db *gorm.DB) BulletinRepository {
	return &bulletinRepository{
		GormRepository: NewGormRepository[models.Bulletin](db),
	}
}

// GormDB returns the underlying GORM database connection.
func (r *bulletinRepository) GormDB() *gorm.DB {
	return r.db
}

// Create inserts a new bulletin and returns the created ID.
func (r *bulletinRepository) Create(ctx context.Context, stationID int64, filename, audioFile string, duration float64, fileSize int64, storyCount int) (int64, error) {
	bulletin := &models.Bulletin{
		StationID:       stationID,
		Filename:        filename,
		AudioFile:       audioFile,
		DurationSeconds: duration,
		FileSize:        fileSize,
		StoryCount:      storyCount,
	}

	if err := r.db.WithContext(ctx).Create(bulletin).Error; err != nil {
		if IsDuplicateKeyError(err) {
			return 0, ErrDuplicateKey
		}
		return 0, err
	}

	return bulletin.ID, nil
}

// GetByID retrieves a bulletin by ID with station name.
func (r *bulletinRepository) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	err := r.db.WithContext(ctx).
		Select("bulletins.*, stations.name as station_name").
		Joins("JOIN stations ON bulletins.station_id = stations.id").
		First(&bulletin, id).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &bulletin, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (r *bulletinRepository) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	query := r.db.WithContext(ctx).
		Select("bulletins.*, stations.name as station_name").
		Joins("JOIN stations ON bulletins.station_id = stations.id").
		Scopes(ByStationID(stationID))

	if maxAge != nil {
		minTime := time.Now().Add(-*maxAge)
		query = query.Where("bulletins.created_at >= ?", minTime)
	}

	err := query.Scopes(OrderByCreatedDesc).
		First(&bulletin).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &bulletin, nil
}

// LinkStories creates bulletin-story relationship records.
func (r *bulletinRepository) LinkStories(ctx context.Context, bulletinID int64, storyIDs []int64) error {
	if len(storyIDs) == 0 {
		return nil
	}

	// Build slice of BulletinStory records
	bulletinStories := make([]models.BulletinStory, len(storyIDs))
	for i, storyID := range storyIDs {
		bulletinStories[i] = models.BulletinStory{
			BulletinID: bulletinID,
			StoryID:    storyID,
			StoryOrder: i,
		}
	}

	// Batch insert all records
	if err := r.db.WithContext(ctx).Create(&bulletinStories).Error; err != nil {
		if IsDuplicateKeyError(err) {
			return ErrDuplicateKey
		}
		return err
	}

	return nil
}
