// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
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
	Metadata  interface{}
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

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// storyRepository implements StoryRepository.
type storyRepository struct {
	*BaseRepository[models.Story]
}

// NewStoryRepository creates a new story repository.
func NewStoryRepository(db *sqlx.DB) StoryRepository {
	return &storyRepository{
		BaseRepository: NewBaseRepository[models.Story](db, "stories"),
	}
}

// Create inserts a new story and returns the created record with voice info.
func (r *storyRepository) Create(ctx context.Context, data *StoryCreateData) (*models.Story, error) {
	q := r.getQueryable(ctx)

	// Convert metadata to JSON if not nil
	var metadataJSON interface{}
	if data.Metadata != nil {
		jsonBytes, err := json.Marshal(data.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = string(jsonBytes)
	}

	result, err := q.ExecContext(ctx,
		`INSERT INTO stories (title, text, voice_id, status, start_date, end_date,
            monday, tuesday, wednesday, thursday, friday, saturday, sunday, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		data.Title, data.Text, data.VoiceID, data.Status, data.StartDate, data.EndDate,
		data.Monday, data.Tuesday, data.Wednesday, data.Thursday, data.Friday, data.Saturday, data.Sunday, metadataJSON,
	)
	if err != nil {
		return nil, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return r.GetByIDWithVoice(ctx, id)
}

// GetByIDWithVoice retrieves a story with voice information via JOIN.
func (r *storyRepository) GetByIDWithVoice(ctx context.Context, id int64) (*models.Story, error) {
	q := r.getQueryable(ctx)

	var story models.Story
	query := `SELECT s.*, COALESCE(v.name, '') as voice_name
              FROM stories s
              LEFT JOIN voices v ON s.voice_id = v.id
              WHERE s.id = ?`

	if err := q.GetContext(ctx, &story, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &story, nil
}

// Update updates a story with type-safe fields.
func (r *storyRepository) Update(ctx context.Context, id int64, updates *StoryUpdate) error {
	if updates == nil {
		return nil
	}

	q := r.getQueryable(ctx)

	setClauses := make([]string, 0, 16)
	args := make([]interface{}, 0, 16)

	addFieldUpdate(&setClauses, &args, "title", updates.Title)
	addFieldUpdate(&setClauses, &args, "text", updates.Text)
	addFieldUpdate(&setClauses, &args, "voice_id", updates.VoiceID)
	addFieldUpdate(&setClauses, &args, "status", updates.Status)
	addFieldUpdate(&setClauses, &args, "start_date", updates.StartDate)
	addFieldUpdate(&setClauses, &args, "end_date", updates.EndDate)
	addFieldUpdate(&setClauses, &args, "monday", updates.Monday)
	addFieldUpdate(&setClauses, &args, "tuesday", updates.Tuesday)
	addFieldUpdate(&setClauses, &args, "wednesday", updates.Wednesday)
	addFieldUpdate(&setClauses, &args, "thursday", updates.Thursday)
	addFieldUpdate(&setClauses, &args, "friday", updates.Friday)
	addFieldUpdate(&setClauses, &args, "saturday", updates.Saturday)
	addFieldUpdate(&setClauses, &args, "sunday", updates.Sunday)
	addFieldUpdate(&setClauses, &args, "metadata", updates.Metadata)
	addFieldUpdate(&setClauses, &args, "audio_file", updates.AudioFile)
	addFieldUpdate(&setClauses, &args, "duration_seconds", updates.DurationSeconds)

	if len(setClauses) == 0 {
		return nil
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE stories SET %s WHERE id = ?", strings.Join(setClauses, ", "))

	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// SoftDelete sets the deleted_at timestamp.
func (r *storyRepository) SoftDelete(ctx context.Context, id int64) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Restore clears the deleted_at timestamp.
func (r *storyRepository) Restore(ctx context.Context, id int64) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "UPDATE stories SET deleted_at = NULL WHERE id = ?", id)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ExistsIncludingDeleted checks if a story exists (including soft-deleted).
func (r *storyRepository) ExistsIncludingDeleted(ctx context.Context, id int64) (bool, error) {
	q := r.getQueryable(ctx)

	var exists bool
	err := q.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stories WHERE id = ?)", id)
	return exists, ParseDBError(err)
}

// UpdateAudio updates the audio file and duration.
func (r *storyRepository) UpdateAudio(ctx context.Context, id int64, audioFile string, duration float64) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		"UPDATE stories SET audio_file = ?, duration_seconds = ? WHERE id = ?",
		audioFile, duration, id,
	)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdateStatus updates the story status.
func (r *storyRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "UPDATE stories SET status = ? WHERE id = ?", status, id)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// GetStoriesForBulletin retrieves eligible stories for bulletin generation.
func (r *storyRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]models.Story, error) {
	q := r.getQueryable(ctx)

	weekdayColumn := getWeekdayColumn(date.Weekday())

	var stories []models.Story
	query := fmt.Sprintf(`
        SELECT s.*, v.name as voice_name, sv.audio_file as voice_jingle, sv.mix_point as voice_mix_point
        FROM stories s
        JOIN voices v ON s.voice_id = v.id
        JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = s.voice_id
        WHERE s.deleted_at IS NULL
        AND s.audio_file IS NOT NULL
        AND s.audio_file != ''
        AND s.start_date <= ?
        AND s.end_date >= ?
        AND s.%s = 1
        ORDER BY RAND()
        LIMIT ?`, weekdayColumn)

	err := q.SelectContext(ctx, &stories, query, stationID, date, date, limit)
	return stories, ParseDBError(err)
}

// getWeekdayColumn returns the database column for a weekday.
func getWeekdayColumn(weekday time.Weekday) string {
	columns := map[time.Weekday]string{
		time.Monday:    "monday",
		time.Tuesday:   "tuesday",
		time.Wednesday: "wednesday",
		time.Thursday:  "thursday",
		time.Friday:    "friday",
		time.Saturday:  "saturday",
		time.Sunday:    "sunday",
	}
	if col, ok := columns[weekday]; ok {
		return col
	}
	return "monday"
}
