// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository/updates"
	"gorm.io/gorm"
)

// StoryUpdate contains optional fields for updating a story.
// Nil pointer fields are not updated.
type StoryUpdate struct {
	Title           *string    `db:"title"`
	Text            *string    `db:"text"`
	VoiceID         *int64     `db:"voice_id"`
	Status          *string    `db:"status"`
	StartDate       *time.Time `db:"start_date"`
	EndDate         *time.Time `db:"end_date"`
	Monday          *bool      `db:"monday"`
	Tuesday         *bool      `db:"tuesday"`
	Wednesday       *bool      `db:"wednesday"`
	Thursday        *bool      `db:"thursday"`
	Friday          *bool      `db:"friday"`
	Saturday        *bool      `db:"saturday"`
	Sunday          *bool      `db:"sunday"`
	Metadata        *string    `db:"metadata"` // Already JSON string
	AudioFile       *string    `db:"audio_file"`
	DurationSeconds *float64   `db:"duration_seconds"`
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
		return nil, ParseDBError(err)
	}

	return r.GetByIDWithVoice(ctx, story.ID)
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

	// Populate the VoiceName field from the preloaded Voice relation
	if story.Voice != nil {
		story.VoiceName = story.Voice.Name
	}

	return &story, nil
}

// Update updates a story with type-safe fields.
func (r *storyRepository) Update(ctx context.Context, id int64, u *StoryUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := updates.ToMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.Story{}).Where("id = ?", id).Updates(updateMap)
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
	result := r.db.WithContext(ctx).Delete(&models.Story{}, id)
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
	result := r.db.WithContext(ctx).Unscoped().Model(&models.Story{}).
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
	result := r.db.WithContext(ctx).Model(&models.Story{}).
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
	result := r.db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Update("status", status)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// List retrieves stories with filtering, sorting, and pagination.
// Supports soft delete filtering via Status field: "active", "deleted", or "all".
func (r *storyRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Build base query with voice preload
	baseQuery := r.db.WithContext(ctx).Model(&models.Story{}).Preload("Voice")

	// Apply soft delete filtering based on status
	switch query.Status {
	case "deleted":
		baseQuery = baseQuery.Unscoped().Where("deleted_at IS NOT NULL")
	case "all":
		baseQuery = baseQuery.Unscoped()
	default: // "active" or empty
		// GORM automatically filters deleted_at IS NULL for models with gorm.DeletedAt
	}

	// Apply search across title and text fields
	if query.Search != "" {
		searchPattern := "%" + query.Search + "%"
		baseQuery = baseQuery.Where("title LIKE ? OR text LIKE ?", searchPattern, searchPattern)
	}

	// Apply filters
	for _, filter := range query.Filters {
		baseQuery = applyStoryFilter(baseQuery, filter)
	}

	// Count total before pagination
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sort := range query.Sort {
			direction := "ASC"
			if sort.Direction == SortDesc {
				direction = "DESC"
			}
			// Validate field names to prevent SQL injection
			if isValidStoryField(sort.Field) {
				baseQuery = baseQuery.Order(sort.Field + " " + direction)
			}
		}
	} else {
		// Default sort by created_at descending
		baseQuery = baseQuery.Order("created_at DESC")
	}

	// Apply pagination
	baseQuery = baseQuery.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var stories []models.Story
	if err := baseQuery.Find(&stories).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Populate VoiceName from preloaded Voice relation
	for i := range stories {
		if stories[i].Voice != nil {
			stories[i].VoiceName = stories[i].Voice.Name
		}
	}

	return &ListResult[models.Story]{
		Data:   stories,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}

// storyValidFields contains the allowed fields for story queries (for SQL injection prevention).
var storyValidFields = map[string]bool{
	"id":               true,
	"title":            true,
	"text":             true,
	"voice_id":         true,
	"status":           true,
	"start_date":       true,
	"end_date":         true,
	"duration_seconds": true,
	"created_at":       true,
	"updated_at":       true,
	"deleted_at":       true,
}

// isValidStoryField validates that a field name is safe for use in queries.
func isValidStoryField(field string) bool {
	return storyValidFields[field]
}

// applyStoryFilter applies a single filter condition to the query with field validation.
func applyStoryFilter(query *gorm.DB, filter FilterCondition) *gorm.DB {
	// Validate field name to prevent SQL injection
	if !isValidStoryField(filter.Field) {
		return query
	}

	switch filter.Operator {
	case FilterEquals:
		return query.Where(filter.Field+" = ?", filter.Value)
	case FilterNotEquals:
		return query.Where(filter.Field+" != ?", filter.Value)
	case FilterGreaterThan:
		return query.Where(filter.Field+" > ?", filter.Value)
	case FilterGreaterOrEq:
		return query.Where(filter.Field+" >= ?", filter.Value)
	case FilterLessThan:
		return query.Where(filter.Field+" < ?", filter.Value)
	case FilterLessOrEq:
		return query.Where(filter.Field+" <= ?", filter.Value)
	case FilterLike:
		return query.Where(filter.Field+" LIKE ?", "%"+filter.Value.(string)+"%")
	case FilterIn:
		return query.Where(filter.Field+" IN ?", filter.Value)
	default:
		return query.Where(filter.Field+" = ?", filter.Value)
	}
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
		return nil, ParseDBError(err)
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
