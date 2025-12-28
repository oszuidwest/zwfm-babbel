// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// StoryUpdate contains optional fields for updating a story.
// Nil pointer fields are not updated.
type StoryUpdate struct {
	Title           *string
	Text            *string
	VoiceID         *int64
	Status          *string
	StartDate       *time.Time
	EndDate         *time.Time
	Monday          *bool
	Tuesday         *bool
	Wednesday       *bool
	Thursday        *bool
	Friday          *bool
	Saturday        *bool
	Sunday          *bool
	Metadata        *string // Already JSON string
	AudioFile       *string
	DurationSeconds *float64
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

	// Audio operations
	UpdateAudio(ctx context.Context, id int64, audioFile string, duration float64) error

	// Status operations
	UpdateStatus(ctx context.Context, id int64, status string) error

	// Bulletin-related queries
	GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]models.Story, error)
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

	if err := r.db.WithContext(ctx).Create(story).Error; err != nil {
		return nil, ParseGormError(err)
	}

	return r.GetByIDWithVoice(ctx, story.ID)
}

// GetByIDWithVoice retrieves a story with voice information via Preload.
func (r *storyRepository) GetByIDWithVoice(ctx context.Context, id int64) (*models.Story, error) {
	var story models.Story

	err := r.db.WithContext(ctx).
		Preload("Voice").
		First(&story, id).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ParseGormError(err)
	}

	// Populate the VoiceName field from the preloaded Voice relation
	if story.Voice != nil {
		story.VoiceName = story.Voice.Name
	}

	return &story, nil
}

// Update updates a story with type-safe fields.
func (r *storyRepository) Update(ctx context.Context, id int64, updates *StoryUpdate) error {
	if updates == nil {
		return nil
	}

	// Build the updates map
	updateMap := make(map[string]any)

	if updates.Title != nil {
		updateMap["title"] = *updates.Title
	}
	if updates.Text != nil {
		updateMap["text"] = *updates.Text
	}
	if updates.VoiceID != nil {
		updateMap["voice_id"] = *updates.VoiceID
	}
	if updates.Status != nil {
		updateMap["status"] = *updates.Status
	}
	if updates.StartDate != nil {
		updateMap["start_date"] = *updates.StartDate
	}
	if updates.EndDate != nil {
		updateMap["end_date"] = *updates.EndDate
	}
	if updates.Monday != nil {
		updateMap["monday"] = *updates.Monday
	}
	if updates.Tuesday != nil {
		updateMap["tuesday"] = *updates.Tuesday
	}
	if updates.Wednesday != nil {
		updateMap["wednesday"] = *updates.Wednesday
	}
	if updates.Thursday != nil {
		updateMap["thursday"] = *updates.Thursday
	}
	if updates.Friday != nil {
		updateMap["friday"] = *updates.Friday
	}
	if updates.Saturday != nil {
		updateMap["saturday"] = *updates.Saturday
	}
	if updates.Sunday != nil {
		updateMap["sunday"] = *updates.Sunday
	}
	if updates.Metadata != nil {
		updateMap["metadata"] = *updates.Metadata
	}
	if updates.AudioFile != nil {
		updateMap["audio_file"] = *updates.AudioFile
	}
	if updates.DurationSeconds != nil {
		updateMap["duration_seconds"] = *updates.DurationSeconds
	}

	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.Story{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return ParseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// SoftDelete sets the deleted_at timestamp.
// GORM handles soft deletes automatically for models with gorm.DeletedAt.
func (r *storyRepository) SoftDelete(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&models.Story{}, id)
	if result.Error != nil {
		return ParseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Restore clears the deleted_at timestamp.
func (r *storyRepository) Restore(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Unscoped().Model(&models.Story{}).
		Where("id = ?", id).
		Update("deleted_at", nil)
	if result.Error != nil {
		return ParseGormError(result.Error)
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
		return false, ParseGormError(err)
	}
	return count > 0, nil
}

// UpdateAudio updates the audio file and duration.
func (r *storyRepository) UpdateAudio(ctx context.Context, id int64, audioFile string, duration float64) error {
	result := r.db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"audio_file":       audioFile,
			"duration_seconds": duration,
		})
	if result.Error != nil {
		return ParseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateStatus updates the story status.
func (r *storyRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	result := r.db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return ParseGormError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// GetStoriesForBulletin retrieves eligible stories for bulletin generation.
func (r *storyRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]models.Story, error) {
	var stories []models.Story

	// Get the weekday column name
	weekdayColumn := getWeekdayColumn(date.Weekday())

	// Build the query with proper joins
	err := r.db.WithContext(ctx).
		Table("stories s").
		Select("s.*, v.name as voice_name, sv.audio_file as voice_jingle, sv.mix_point as voice_mix_point").
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
		return nil, ParseGormError(err)
	}

	return stories, nil
}

// getWeekdayColumn returns the column name for the given weekday.
func getWeekdayColumn(weekday time.Weekday) string {
	days := map[time.Weekday]string{
		time.Monday:    "s.monday",
		time.Tuesday:   "s.tuesday",
		time.Wednesday: "s.wednesday",
		time.Thursday:  "s.thursday",
		time.Friday:    "s.friday",
		time.Saturday:  "s.saturday",
		time.Sunday:    "s.sunday",
	}
	if col, ok := days[weekday]; ok {
		return col
	}
	return "s.monday" // Default fallback
}

// ParseGormError converts GORM errors to repository errors.
func ParseGormError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	// Use the existing ParseDBError for MySQL-specific error handling
	return ParseDBError(err)
}
