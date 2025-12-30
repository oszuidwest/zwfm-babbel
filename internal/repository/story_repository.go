// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// StoryUpdate contains optional fields for updating a story.
// Nil pointer fields are not updated. Clear* flags explicitly set fields to NULL.
type StoryUpdate struct {
	Title           *string            `gorm:"column:title"`
	Text            *string            `gorm:"column:text"`
	VoiceID         *int64             `gorm:"column:voice_id"`
	Status          *string            `gorm:"column:status"`
	StartDate       *time.Time         `gorm:"column:start_date"`
	EndDate         *time.Time         `gorm:"column:end_date"`
	Weekdays        *models.Weekdays   `gorm:"column:weekdays"`
	Metadata        *datatypes.JSONMap `gorm:"column:metadata"`
	AudioFile       *string            `gorm:"column:audio_file"`
	DurationSeconds *float64           `gorm:"column:duration_seconds"`

	// Clear flags - when true, explicitly set the field to NULL
	ClearVoiceID         bool `gorm:"-"`
	ClearAudioFile       bool `gorm:"-"`
	ClearDurationSeconds bool `gorm:"-"`
	ClearMetadata        bool `gorm:"-"`
}

// hasUpdates is no longer needed - BuildUpdateMap handles empty check

// StoryCreateData contains the data for creating a story.
type StoryCreateData struct {
	Title     string
	Text      string
	VoiceID   *int64
	Status    string
	StartDate time.Time
	EndDate   time.Time
	Weekdays  models.Weekdays
	Metadata  *datatypes.JSONMap
}

// StoryRepository defines the interface for story data access.
type StoryRepository interface {
	// CRUD operations
	Create(ctx context.Context, data *StoryCreateData) (*models.Story, error)
	GetByID(ctx context.Context, id int64) (*models.Story, error)
	GetByIDWithVoice(ctx context.Context, id int64) (*models.Story, error)
	Update(ctx context.Context, id int64, updates *StoryUpdate) error

	// Soft delete operations
	SoftDelete(ctx context.Context, id int64) error
	Restore(ctx context.Context, id int64) error

	// Query operations
	Exists(ctx context.Context, id int64) (bool, error)
	ExistsIncludingDeleted(ctx context.Context, id int64) (bool, error)
	List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error)

	// Audio operations
	UpdateAudio(ctx context.Context, id int64, audioFile string, duration float64) error

	// Status operations
	UpdateStatus(ctx context.Context, id int64, status string) error

	// Bulletin-related queries
	GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]BulletinStoryData, error)
}

// storyRepository implements StoryRepository using GORM.
type storyRepository struct {
	*GormRepository[models.Story]
}

// NewStoryRepository creates a new story repository.
func NewStoryRepository(db *gorm.DB) StoryRepository {
	return &storyRepository{
		GormRepository: NewGormRepository[models.Story](db),
	}
}

// Create inserts a new story and returns the created record with voice info.
func (r *storyRepository) Create(ctx context.Context, data *StoryCreateData) (*models.Story, error) {
	story := &models.Story{
		Title:     data.Title,
		Text:      data.Text,
		VoiceID:   data.VoiceID,
		Status:    models.StoryStatus(data.Status),
		StartDate: data.StartDate,
		EndDate:   data.EndDate,
		Weekdays:  data.Weekdays,
		Metadata:  data.Metadata,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(story).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Load voice relation on the created record (avoids separate GetByID query)
	if story.VoiceID != nil {
		if err := db.WithContext(ctx).Preload("Voice").First(story, story.ID).Error; err != nil {
			return nil, ParseDBError(err)
		}
	}

	return story, nil
}

// GetByID retrieves a story by ID with its associated voice.
func (r *storyRepository) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	return r.GetByIDWithPreload(ctx, id, "Voice")
}

// GetByIDWithVoice retrieves a story with its associated voice.
//
// Deprecated: Use GetByID instead, which includes voice information.
func (r *storyRepository) GetByIDWithVoice(ctx context.Context, id int64) (*models.Story, error) {
	return r.GetByIDWithPreload(ctx, id, "Voice")
}

// Update updates a story. Nil pointer fields are skipped; Clear* flags set fields to NULL.
func (r *storyRepository) Update(ctx context.Context, id int64, u *StoryUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	return r.UpdateByID(ctx, id, updateMap)
}

// SoftDelete marks a story as deleted without removing it from the database.
func (r *storyRepository) SoftDelete(ctx context.Context, id int64) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Delete(&models.Story{}, id)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Restore clears the deleted_at timestamp.
func (r *storyRepository) Restore(ctx context.Context, id int64) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Unscoped().Model(&models.Story{}).
		Where("id = ?", id).
		Update("deleted_at", nil)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ExistsIncludingDeleted reports whether a story exists, including soft-deleted stories.
func (r *storyRepository) ExistsIncludingDeleted(ctx context.Context, id int64) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Unscoped().Model(&models.Story{}).Where("id = ?", id).Count(&count).Error
	if err != nil {
		return false, ParseDBError(err)
	}
	return count > 0, nil
}

// UpdateAudio updates the audio file and duration.
func (r *storyRepository) UpdateAudio(ctx context.Context, id int64, audioFile string, duration float64) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"audio_file":       audioFile,
			"duration_seconds": duration,
		})
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateStatus updates the story status.
func (r *storyRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Updates(map[string]any{"status": status})
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// storyFieldMapping maps API field names to database columns for stories.
var storyFieldMapping = FieldMapping{
	"id":               "id",
	"title":            "title",
	"text":             "text",
	"voice_id":         "voice_id",
	"audio_url":        "audio_file", // Maps API field to DB column for filtering
	"status":           "status",
	"start_date":       "start_date",
	"end_date":         "end_date",
	"duration_seconds": "duration_seconds",
	"weekdays":         "weekdays",
	"created_at":       "created_at",
	"updated_at":       "updated_at",
	"deleted_at":       "deleted_at",
}

// storySearchFields defines which fields are searchable for stories.
var storySearchFields = []string{"title", "text"}

// List retrieves stories with filtering, sorting, and pagination.
// Supports soft delete filtering via Trashed field: "", "only", or "with".
func (r *storyRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Build base query with voice preload and soft delete filtering
	db := r.db.WithContext(ctx).Model(&models.Story{}).Preload("Voice")
	db = ApplySoftDeleteFilter(db, query.Trashed)

	return ApplyListQuery[models.Story](db, query, storyFieldMapping, storySearchFields, "created_at DESC")
}

// BulletinStoryData contains story data with station-specific mix point for audio processing.
type BulletinStoryData struct {
	models.Story
	MixPoint float64 `gorm:"column:mix_point"`
}

// GetStoriesForBulletin retrieves eligible stories for bulletin generation.
// Returns stories with station-specific mix point data needed for audio processing.
func (r *storyRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]BulletinStoryData, error) {
	var stories []BulletinStoryData

	// Calculate bitmask for the current weekday (Sunday=1, Monday=2, etc.)
	// time.Weekday is always in range [0,6], safe to convert to uint8
	weekdayBit := 1 << uint8(date.Weekday()) // #nosec G115

	// Build the query with proper joins to get mix_point from station_voices.
	// Using Model() ensures GORM's soft delete filtering is applied automatically.
	// Note: Voice preload not needed - only VoiceID is used for jingle lookup.
	err := r.db.WithContext(ctx).
		Model(&models.Story{}).
		Select("stories.*, sv.mix_point").
		Joins("JOIN voices v ON stories.voice_id = v.id").
		Joins("JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = stories.voice_id", stationID).
		Where("stories.audio_file IS NOT NULL").
		Where("stories.audio_file != ''").
		Where("stories.start_date <= ?", date).
		Where("stories.end_date >= ?", date).
		Where("stories.weekdays & ? > 0", weekdayBit).
		Order("RAND()").
		Limit(limit).
		Find(&stories).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return stories, nil
}
