// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// StoryUpdate contains optional fields for updating a story.
// Nil pointer fields are not updated.
type StoryUpdate struct {
	Title           *string    `gorm:"column:title"`
	Text            *string    `gorm:"column:text"`
	VoiceID         *int64     `gorm:"column:voice_id"`
	Status          *string    `gorm:"column:status"`
	StartDate       *time.Time `gorm:"column:start_date"`
	EndDate         *time.Time `gorm:"column:end_date"`
	Monday          *bool      `gorm:"column:monday"`
	Tuesday         *bool      `gorm:"column:tuesday"`
	Wednesday       *bool      `gorm:"column:wednesday"`
	Thursday        *bool      `gorm:"column:thursday"`
	Friday          *bool      `gorm:"column:friday"`
	Saturday        *bool      `gorm:"column:saturday"`
	Sunday          *bool      `gorm:"column:sunday"`
	Metadata        *string    `gorm:"column:metadata"` // Already JSON string
	AudioFile       *string    `gorm:"column:audio_file"`
	DurationSeconds *float64   `gorm:"column:duration_seconds"`
}

// StoryCreateData contains the data for creating a story.
type StoryCreateData struct {
	Title     string
	Text      string
	VoiceID   *int64
	Status    string
	StartDate time.Time
	EndDate   time.Time
	Monday    bool
	Tuesday   bool
	Wednesday bool
	Thursday  bool
	Friday    bool
	Saturday  bool
	Sunday    bool
	Metadata  any
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
	// Convert metadata to JSON if not nil
	var metadataJSON *string
	if data.Metadata != nil {
		jsonBytes, err := json.Marshal(data.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		jsonStr := string(jsonBytes)
		metadataJSON = &jsonStr
	}

	story := &models.Story{
		Title:     data.Title,
		Text:      data.Text,
		VoiceID:   data.VoiceID,
		Status:    models.StoryStatus(data.Status),
		StartDate: data.StartDate,
		EndDate:   data.EndDate,
		Monday:    data.Monday,
		Tuesday:   data.Tuesday,
		Wednesday: data.Wednesday,
		Thursday:  data.Thursday,
		Friday:    data.Friday,
		Saturday:  data.Saturday,
		Sunday:    data.Sunday,
		Metadata:  metadataJSON,
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

// GetByIDWithVoice retrieves a story with voice information via Preload.
func (r *storyRepository) GetByIDWithVoice(ctx context.Context, id int64) (*models.Story, error) {
	var story models.Story

	err := r.db.WithContext(ctx).
		Preload("Voice").
		First(&story, id).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &story, nil
}

// Update updates a story with type-safe fields.
func (r *storyRepository) Update(ctx context.Context, id int64, u *StoryUpdate) error {
	if u == nil {
		return nil
	}

	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Model(&models.Story{}).Where("id = ?", id).Updates(u)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// SoftDelete sets the deleted_at timestamp.
// GORM handles soft deletes automatically for models with gorm.DeletedAt.
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

// ExistsIncludingDeleted checks if a story exists (including soft-deleted).
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
	"status":           "status",
	"start_date":       "start_date",
	"end_date":         "end_date",
	"duration_seconds": "duration_seconds",
	"created_at":       "created_at",
	"updated_at":       "updated_at",
	"deleted_at":       "deleted_at",
}

// storySearchFields defines which fields are searchable for stories.
var storySearchFields = []string{"title", "text"}

// List retrieves stories with filtering, sorting, and pagination.
// Supports soft delete filtering via Status field: "active", "deleted", or "all".
func (r *storyRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Build base query with voice preload and soft delete filtering
	db := r.db.WithContext(ctx).Model(&models.Story{}).Preload("Voice")
	db = ApplySoftDeleteFilter(db, query.Status)

	return ApplyListQuery[models.Story](db, query, storyFieldMapping, storySearchFields, "created_at DESC")
}

// BulletinStoryData contains story data with station-specific audio processing info.
// This is used for bulletin generation where we need jingle mix points.
type BulletinStoryData struct {
	models.Story
	MixPoint float64 `gorm:"column:mix_point"`
}

// GetStoriesForBulletin retrieves eligible stories for bulletin generation.
// Returns stories with station-specific mix point data needed for audio processing.
func (r *storyRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]BulletinStoryData, error) {
	var stories []BulletinStoryData

	// Get the weekday column name
	weekdayColumn := getWeekdayColumn(date.Weekday())

	// Build the query with proper joins to get mix_point from station_voices
	err := r.db.WithContext(ctx).
		Table("stories s").
		Select("s.*, sv.mix_point").
		Joins("JOIN voices v ON s.voice_id = v.id").
		Joins("JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = s.voice_id", stationID).
		Where("s.deleted_at IS NULL").
		Where("s.audio_file IS NOT NULL").
		Where("s.audio_file != ''").
		Where("s.start_date <= ?", date).
		Where("s.end_date >= ?", date).
		Where(weekdayColumn+" = ?", true).
		Order("RAND()").
		Limit(limit).
		Find(&stories).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return stories, nil
}

// weekdayColumns maps time.Weekday to the corresponding story column name.
// Package-level variable to avoid allocation on every GetStoriesForBulletin call.
var weekdayColumns = map[time.Weekday]string{
	time.Monday:    "s.monday",
	time.Tuesday:   "s.tuesday",
	time.Wednesday: "s.wednesday",
	time.Thursday:  "s.thursday",
	time.Friday:    "s.friday",
	time.Saturday:  "s.saturday",
	time.Sunday:    "s.sunday",
}

// getWeekdayColumn returns the column name for the given weekday.
func getWeekdayColumn(weekday time.Weekday) string {
	if col, ok := weekdayColumns[weekday]; ok {
		return col
	}
	return "s.monday" // Default fallback
}
