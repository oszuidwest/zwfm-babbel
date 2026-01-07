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
	GetBulletinStories(ctx context.Context, bulletinID int64, limit, offset int) ([]models.BulletinStory, int64, error)
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

// GetByID retrieves a bulletin by ID with its associated station.
func (r *bulletinRepository) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).
		Joins("Station").
		First(&bulletin, id).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins created within that duration.
func (r *bulletinRepository) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	query := r.db.WithContext(ctx).
		Joins("Station").
		Where("bulletins.station_id = ?", stationID)

	if maxAge != nil {
		minTime := time.Now().Add(-*maxAge)
		query = query.Where("bulletins.created_at >= ?", minTime)
	}

	err := query.Order("bulletins.created_at DESC").
		First(&bulletin).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// LinkStories creates bulletin-story relationship records preserving story order.
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
	"id":               "bulletins.id",
	"station_id":       "bulletins.station_id",
	"filename":         "bulletins.filename",
	"duration_seconds": "bulletins.duration_seconds",
	"file_size":        "bulletins.file_size",
	"story_count":      "bulletins.story_count",
	"created_at":       "bulletins.created_at",
}

// bulletinSearchFields defines which fields are searchable for bulletins.
var bulletinSearchFields = []string{"bulletins.filename"}

// List retrieves bulletins with pagination, filtering, and sorting.
func (r *bulletinRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Joins("Station")

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC", "bulletins")
}

// Exists reports whether a bulletin with the given ID exists.
func (r *bulletinRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// GetBulletinStories retrieves stories included in a specific bulletin with pagination.
func (r *bulletinRepository) GetBulletinStories(ctx context.Context, bulletinID int64, limit, offset int) ([]models.BulletinStory, int64, error) {
	var bulletinStories []models.BulletinStory
	var total int64

	db := r.db.WithContext(ctx).
		Model(&models.BulletinStory{}).
		Where("bulletin_id = ?", bulletinID)

	// Count total before pagination
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, ParseDBError(err)
	}

	// Apply pagination and fetch with preloads
	query := r.db.WithContext(ctx).
		Preload("Story").
		Preload("Story.Voice").
		Where("bulletin_id = ?", bulletinID).
		Order("story_order ASC")

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	if err := query.Find(&bulletinStories).Error; err != nil {
		return nil, 0, ParseDBError(err)
	}

	return bulletinStories, total, nil
}

// GetStationBulletins retrieves bulletins for a specific station with pagination.
func (r *bulletinRepository) GetStationBulletins(ctx context.Context, stationID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Joins("Station").
		Where("bulletins.station_id = ?", stationID)

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC", "bulletins")
}

// GetStoryBulletinHistory retrieves bulletins that included a specific story.
func (r *bulletinRepository) GetStoryBulletinHistory(ctx context.Context, storyID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Joins("Station").
		Joins("JOIN bulletin_stories ON bulletins.id = bulletin_stories.bulletin_id").
		Where("bulletin_stories.story_id = ?", storyID)

	return ApplyListQuery[models.Bulletin](db, query, bulletinFieldMapping, bulletinSearchFields, "created_at DESC", "bulletins")
}
