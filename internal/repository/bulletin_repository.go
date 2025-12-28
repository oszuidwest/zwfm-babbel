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
		if IsDuplicateKeyError(err) {
			return ErrDuplicateKey
		}
		return err
	}

	return nil
}

// List retrieves bulletins with pagination, filtering, and sorting.
func (r *bulletinRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Bulletin], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Start building the query with station name join
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Select("bulletins.*, stations.name as station_name").
		Joins("JOIN stations ON bulletins.station_id = stations.id")

	// Apply filters
	for _, filter := range query.Filters {
		db = applyFilter(db, filter)
	}

	// Apply search on filename
	if query.Search != "" {
		db = db.Where("bulletins.filename LIKE ?", "%"+query.Search+"%")
	}

	// Count total before pagination
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sort := range query.Sort {
			direction := "ASC"
			if sort.Direction == SortDesc {
				direction = "DESC"
			}
			db = db.Order(sort.Field + " " + direction)
		}
	} else {
		db = db.Order("bulletins.created_at DESC")
	}

	// Apply pagination
	db = db.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var bulletins []models.Bulletin
	if err := db.Find(&bulletins).Error; err != nil {
		return nil, err
	}

	return &ListResult[models.Bulletin]{
		Data:   bulletins,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}

// Exists checks if a bulletin with the given ID exists.
func (r *bulletinRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// applyFilter applies a single filter condition to the query.
func applyFilter(db *gorm.DB, filter FilterCondition) *gorm.DB {
	switch filter.Operator {
	case FilterEquals:
		return db.Where(filter.Field+" = ?", filter.Value)
	case FilterNotEquals:
		return db.Where(filter.Field+" != ?", filter.Value)
	case FilterGreaterThan:
		return db.Where(filter.Field+" > ?", filter.Value)
	case FilterGreaterOrEq:
		return db.Where(filter.Field+" >= ?", filter.Value)
	case FilterLessThan:
		return db.Where(filter.Field+" < ?", filter.Value)
	case FilterLessOrEq:
		return db.Where(filter.Field+" <= ?", filter.Value)
	case FilterLike:
		return db.Where(filter.Field+" LIKE ?", filter.Value)
	case FilterIn:
		return db.Where(filter.Field+" IN ?", filter.Value)
	default:
		return db.Where(filter.Field+" = ?", filter.Value)
	}
}

// GetBulletinStories retrieves all stories included in a specific bulletin.
func (r *bulletinRepository) GetBulletinStories(ctx context.Context, bulletinID int64) ([]models.BulletinStory, error) {
	var bulletinStories []models.BulletinStory

	err := r.db.WithContext(ctx).
		Select("bulletin_stories.*, stories.title as story_title").
		Joins("JOIN stories ON bulletin_stories.story_id = stories.id").
		Where("bulletin_stories.bulletin_id = ?", bulletinID).
		Order("bulletin_stories.story_order ASC").
		Find(&bulletinStories).Error

	if err != nil {
		return nil, err
	}

	return bulletinStories, nil
}

// GetStationBulletins retrieves bulletins for a specific station with pagination.
func (r *bulletinRepository) GetStationBulletins(ctx context.Context, stationID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Start building the query with station name join
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Select("bulletins.*, stations.name as station_name").
		Joins("JOIN stations ON bulletins.station_id = stations.id").
		Where("bulletins.station_id = ?", stationID)

	// Apply filters
	for _, filter := range query.Filters {
		db = applyFilter(db, filter)
	}

	// Apply search on filename
	if query.Search != "" {
		db = db.Where("bulletins.filename LIKE ?", "%"+query.Search+"%")
	}

	// Count total before pagination
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sort := range query.Sort {
			direction := "ASC"
			if sort.Direction == SortDesc {
				direction = "DESC"
			}
			db = db.Order(sort.Field + " " + direction)
		}
	} else {
		db = db.Order("bulletins.created_at DESC")
	}

	// Apply pagination
	db = db.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var bulletins []models.Bulletin
	if err := db.Find(&bulletins).Error; err != nil {
		return nil, err
	}

	return &ListResult[models.Bulletin]{
		Data:   bulletins,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}

// GetStoryBulletinHistory retrieves bulletins that included a specific story.
func (r *bulletinRepository) GetStoryBulletinHistory(ctx context.Context, storyID int64, query *ListQuery) (*ListResult[models.Bulletin], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Start building the query with joins
	db := r.db.WithContext(ctx).
		Model(&models.Bulletin{}).
		Select("bulletins.*, stations.name as station_name").
		Joins("JOIN stations ON bulletins.station_id = stations.id").
		Joins("JOIN bulletin_stories ON bulletins.id = bulletin_stories.bulletin_id").
		Where("bulletin_stories.story_id = ?", storyID)

	// Apply filters
	for _, filter := range query.Filters {
		db = applyFilter(db, filter)
	}

	// Apply search on filename
	if query.Search != "" {
		db = db.Where("bulletins.filename LIKE ?", "%"+query.Search+"%")
	}

	// Count total before pagination
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sort := range query.Sort {
			direction := "ASC"
			if sort.Direction == SortDesc {
				direction = "DESC"
			}
			db = db.Order(sort.Field + " " + direction)
		}
	} else {
		db = db.Order("bulletins.created_at DESC")
	}

	// Apply pagination
	db = db.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var bulletins []models.Bulletin
	if err := db.Find(&bulletins).Error; err != nil {
		return nil, err
	}

	return &ListResult[models.Bulletin]{
		Data:   bulletins,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}
