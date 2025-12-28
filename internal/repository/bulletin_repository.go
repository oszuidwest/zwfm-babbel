// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
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
	List(ctx context.Context, query *ListQuery) (*ListResult[models.Bulletin], error)
	Exists(ctx context.Context, id int64) (bool, error)
	GetBulletinStories(ctx context.Context, bulletinID int64) ([]models.BulletinStory, error)
	GetStationBulletins(ctx context.Context, stationID int64, query *ListQuery) (*ListResult[models.Bulletin], error)
	GetStoryBulletinHistory(ctx context.Context, storyID int64, query *ListQuery) (*ListResult[models.Bulletin], error)

	// Story linking
	LinkStories(ctx context.Context, bulletinID int64, storyIDs []int64) error
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

// Create inserts a new bulletin and returns the created ID.
// Uses transaction from context if available.
func (r *bulletinRepository) Create(ctx context.Context, stationID int64, filename, audioFile string, duration float64, fileSize int64, storyCount int) (int64, error) {
	bulletin := &models.Bulletin{
		StationID:       stationID,
		Filename:        filename,
		AudioFile:       audioFile,
		DurationSeconds: duration,
		FileSize:        fileSize,
		StoryCount:      storyCount,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(bulletin).Error; err != nil {
		return 0, ParseDBError(err)
	}

	return bulletin.ID, nil
}

// GetByID retrieves a bulletin by ID with preloaded station.
func (r *bulletinRepository) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	err := r.db.WithContext(ctx).
		Preload("Station").
		First(&bulletin, id).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (r *bulletinRepository) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	query := r.db.WithContext(ctx).
		Preload("Station").
		Where("station_id = ?", stationID)

	if maxAge != nil {
		minTime := time.Now().Add(-*maxAge)
		query = query.Where("created_at >= ?", minTime)
	}

	err := query.Order("created_at DESC").
		First(&bulletin).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// LinkStories creates bulletin-story relationship records.
// Uses transaction from context if available.
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

	// Batch insert all records using transaction if available
	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(&bulletinStories).Error; err != nil {
		return ParseDBError(err)
	}

	return nil
}

// bulletinFieldMapping maps API field names to database columns for bulletins.
var bulletinFieldMapping = FieldMapping{
	"id":               "id",
	"station_id":       "station_id",
	"filename":         "filename",
	"duration_seconds": "duration_seconds",
	"file_size":        "file_size",
	"story_count":      "story_count",
	"created_at":       "created_at",
}

// bulletinSearchFields defines which fields are searchable for bulletins.
var bulletinSearchFields = []string{"filename"}

// List retrieves bulletins with pagination, filtering, and sorting.
func (r *bulletinRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Preload("Station")

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC")
}

// Exists checks if a bulletin with the given ID exists.
func (r *bulletinRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// GetBulletinStories retrieves all stories included in a specific bulletin.
func (r *bulletinRepository) GetBulletinStories(ctx context.Context, bulletinID int64) ([]models.BulletinStory, error) {
	var bulletinStories []models.BulletinStory

	err := r.db.WithContext(ctx).
		Preload("Story").
		Where("bulletin_id = ?", bulletinID).
		Order("story_order ASC").
		Find(&bulletinStories).Error

	if err != nil {
		return nil, err
	}

	return bulletinStories, nil
}

// GetStationBulletins retrieves bulletins for a specific station with pagination.
func (r *bulletinRepository) GetStationBulletins(ctx context.Context, stationID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Preload("Station").
		Where("station_id = ?", stationID)

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC")
}

// GetStoryBulletinHistory retrieves bulletins that included a specific story.
func (r *bulletinRepository) GetStoryBulletinHistory(ctx context.Context, storyID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Preload("Station").
		Joins("JOIN bulletin_stories ON bulletins.id = bulletin_stories.bulletin_id").
		Where("bulletin_stories.story_id = ?", storyID)

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC")
}
