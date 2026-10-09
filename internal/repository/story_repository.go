package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// StoryUpdate contains optional fields for updating a story.
// Nil pointer fields are not updated.
type StoryUpdate struct {
	ActorUserID *int64 `gorm:"-"`

	Title      *string            `gorm:"column:title"`
	Text       *string            `gorm:"column:text"`
	VoiceID    *int64             `gorm:"column:voice_id"`
	Status     *string            `gorm:"column:status"`
	StartDate  *time.Time         `gorm:"column:start_date"`
	EndDate    *time.Time         `gorm:"column:end_date"`
	Weekdays   *models.Weekdays   `gorm:"column:weekdays"`
	Metadata   *datatypes.JSONMap `gorm:"column:metadata"`
	IsBreaking *bool              `gorm:"column:is_breaking"`
}

// StoryCreateData contains the data for creating a story.
type StoryCreateData struct {
	ActorUserID *int64

	Title      string
	Text       string
	VoiceID    *int64
	Status     string
	StartDate  time.Time
	EndDate    time.Time
	Weekdays   models.Weekdays
	IsBreaking bool
	Metadata   *datatypes.JSONMap
}

// StoryRepository provides story data access using GORM.
type StoryRepository struct {
	*GormRepository[models.Story]
}

// NewStoryRepository returns a story repository backed by db.
func NewStoryRepository(db *gorm.DB) *StoryRepository {
	return &StoryRepository{
		GormRepository: NewGormRepository[models.Story](db),
	}
}

// Create inserts a story and reloads voice data when a voice is assigned.
func (r *StoryRepository) Create(ctx context.Context, data *StoryCreateData) (*models.Story, error) {
	story := &models.Story{
		Title:      data.Title,
		Text:       data.Text,
		VoiceID:    data.VoiceID,
		Status:     models.StoryStatus(data.Status),
		StartDate:  data.StartDate,
		EndDate:    data.EndDate,
		Weekdays:   data.Weekdays,
		IsBreaking: data.IsBreaking,
		Metadata:   data.Metadata,
	}

	err := NewTxManager(DBFromContext(ctx, r.db)).WithTransaction(ctx, func(ctx context.Context) error {
		db := DBFromContext(ctx, r.db).WithContext(ctx)
		if err := db.Create(story).Error; err != nil {
			return ParseDBError(err)
		}
		values, err := storyAuditValues(db, story.ID)
		if err != nil {
			return err
		}
		if err := RecordAudit(ctx, models.AuditEvent{
			UserID: data.ActorUserID, EntityType: "story", EntityID: story.ID, Action: "create",
		}, nil, values); err != nil {
			return err
		}
		if story.VoiceID != nil {
			return ParseDBError(db.Preload("Voice").First(story, story.ID).Error)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return story, nil
}

// GetByID loads a story with its associated voice.
func (r *StoryRepository) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	return r.GetByIDWithPreload(ctx, id, "Voice")
}

// Update applies non-nil story fields. A voice change only applies while the
// story has no audio or its audio already belongs to that voice; otherwise it
// returns ErrStateConflict.
func (r *StoryRepository) Update(ctx context.Context, id int64, u *StoryUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	return r.withAudit(ctx, id, "update", u.ActorUserID, func(ctx context.Context) error {
		if u.VoiceID == nil {
			return r.UpdateByID(ctx, id, updateMap)
		}

		// The guard is part of the UPDATE so audio uploaded after the caller's
		// read cannot end up paired with a different voice.
		return r.guardedUpdate(ctx, id, updateMap,
			"(COALESCE(audio_file, '') = '' OR voice_id = ?)", *u.VoiceID)
	})
}

// StoryAudioUpdate publishes processed audio together with the voice it was
// produced for. The Expected fields hold the story state read before
// processing started.
type StoryAudioUpdate struct {
	ActorUserID *int64

	IsTTS             bool
	AudioFile         string
	DurationSeconds   float64
	VoiceID           int64
	ExpectedVoiceID   *int64
	ExpectedAudioFile string
}

// UpdateAudio stores new audio and its voice in one statement. It returns
// ErrStateConflict when the story's voice or audio changed since processing
// started.
func (r *StoryRepository) UpdateAudio(ctx context.Context, id int64, u StoryAudioUpdate) error {
	action := "audio"
	if u.IsTTS {
		action = "tts"
	}
	return r.withAudit(ctx, id, action, u.ActorUserID, func(ctx context.Context) error {
		return r.guardedUpdate(ctx, id, map[string]any{
			"voice_id":         u.VoiceID,
			"audio_file":       u.AudioFile,
			"duration_seconds": u.DurationSeconds,
		}, "COALESCE(audio_file, '') = ? AND voice_id <=> ?", u.ExpectedAudioFile, u.ExpectedVoiceID)
	})
}

// guardedUpdate applies updates only when the guard condition holds. When no
// row matches it returns ErrNotFound for a missing story and ErrStateConflict
// otherwise.
func (r *StoryRepository) guardedUpdate(ctx context.Context, id int64, updates map[string]any, guard string, args ...any) error {
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).Model(&models.Story{}).
		Where("id = ?", id).
		Where(guard, args...).
		Updates(updates)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected > 0 {
		return nil
	}

	exists, err := r.Exists(ctx, id)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return ErrStateConflict
}

// SoftDelete marks a story as deleted without removing it from the database.
func (r *StoryRepository) SoftDelete(ctx context.Context, id int64, actorUserID *int64) error {
	return r.withAudit(ctx, id, "delete", actorUserID, func(ctx context.Context) error { return r.Delete(ctx, id) })
}

// Restore clears the deleted_at timestamp.
func (r *StoryRepository) Restore(ctx context.Context, id int64, actorUserID *int64) error {
	return r.withAudit(ctx, id, "restore", actorUserID, func(ctx context.Context) error {
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
	})
}

// UpdateStatus updates the story status.
func (r *StoryRepository) UpdateStatus(ctx context.Context, id int64, status string, actorUserID *int64) error {
	return r.Update(ctx, id, &StoryUpdate{Status: &status, ActorUserID: actorUserID})
}

// ExpireStoriesPastEndDate marks active stories whose end_date has passed as
// expired and returns the number of stories updated.
// GORM automatically excludes soft-deleted records (deleted_at IS NULL).
func (r *StoryRepository) ExpireStoriesPastEndDate(ctx context.Context) (int64, error) {
	var count int64
	err := NewTxManager(DBFromContext(ctx, r.db)).WithTransaction(ctx, func(ctx context.Context) error {
		db := DBFromContext(ctx, r.db).WithContext(ctx)
		var ids []int64
		if err := db.Model(&models.Story{}).Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Where("status = ?", models.StoryStatusActive).Where("end_date < CURDATE()").
			Order("id").Pluck("id", &ids).Error; err != nil {
			return ParseDBError(err)
		}
		if len(ids) == 0 {
			return nil
		}
		result := db.Model(&models.Story{}).Where("id IN ?", ids).Update("status", models.StoryStatusExpired)
		if result.Error != nil {
			return ParseDBError(result.Error)
		}
		for _, id := range ids {
			if err := RecordAudit(ctx, models.AuditEvent{
				EntityType: "story", EntityID: id, Action: "expire",
			}, map[string]any{"status": models.StoryStatusActive},
				map[string]any{"status": models.StoryStatusExpired}); err != nil {
				return err
			}
		}
		count = result.RowsAffected
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// storyFieldMapping maps API field names to database columns for stories.
var storyFieldMapping = FieldMapping{
	"id":               "id",
	"title":            "title",
	"text":             "text",
	"voice_id":         "voice_id",
	"audio_url":        "audio_file", // Maps API field to DB column for filtering
	"has_audio":        "audio_file",
	"status":           "status",
	"start_date":       "start_date",
	"end_date":         "end_date",
	"duration_seconds": "duration_seconds",
	"weekdays":         "weekdays",
	"is_breaking":      "is_breaking",
	"created_at":       "created_at",
	"updated_at":       "updated_at",
	"deleted_at":       "deleted_at",
}

// storySearchFields defines which fields are searchable for stories.
var storySearchFields = []string{"title", "text"}

// List retrieves stories with filtering, sorting, and pagination.
// Supports soft delete filtering via Trashed field: "", "only", or "with".
func (r *StoryRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error) {
	if query == nil {
		query = NewListQuery()
	}

	db := r.db.WithContext(ctx).Model(&models.Story{}).Preload("Voice")
	db = ApplySoftDeleteFilter(db, query.Trashed)

	return ApplyListQuery[models.Story](db, query, storyFieldMapping, storySearchFields, []SortField{{Field: "created_at", Direction: SortDesc}})
}

// BulletinStoryData contains story data with station-specific mix point for audio processing.
type BulletinStoryData struct {
	models.Story
	MixPoint float64 `gorm:"column:mix_point"`
}

// GetStoriesForBulletin retrieves eligible stories for bulletin generation.
// Returns stories with station-specific mix point data needed for audio processing.
//
// Stories must meet ALL criteria to be eligible:
//   - Status is 'active' (excludes 'draft' and 'expired')
//   - Has audio file uploaded
//   - Has voice assigned with station-voice relationship
//   - Current date is within start_date and end_date range
//   - Current weekday matches the story's weekday schedule
//
// Selection priority (determines which stories fill available slots):
//  1. Breaking news stories are selected first (newest by start_date preferred)
//  2. Unused stories today get next priority (newest by start_date preferred)
//  3. If all stories were used today, least-recently-used ones are selected
//  4. RAND() as final tiebreaker for variety
//
// Breaking stories consume slots from the station's limit. Playback order is
// randomized by the caller; this function only determines which stories are selected.
// The rotation resets daily at local midnight and is isolated per station.
func (r *StoryRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]BulletinStoryData, error) {
	var stories []BulletinStoryData

	// time.Weekday is always in range [0,6], safe to convert to uint8.
	weekdayBit := 1 << uint8(date.Weekday()) // #nosec G115

	todayLocal := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())

	// MySQL DATE comparisons should receive date strings, not instants that can
	// be shifted by timezone conversion.
	dateStr := date.Format("2006-01-02")

	// Subquery to find when each story was last used in a bulletin for this station today.
	// Returns NULL if story hasn't been used today, otherwise the most recent usage timestamp.
	lastUsedSubquery := `(
		SELECT MAX(b.created_at)
		FROM bulletin_stories bs
		JOIN bulletins b ON bs.bulletin_id = b.id
		WHERE bs.story_id = stories.id
		  AND b.station_id = ?
		  AND b.created_at >= ?
	)`

	// Build the query with breaking news priority + fair rotation ordering:
	// 1. is_breaking DESC                 → breaking stories selected first
	// 2. CASE for breaking: start_date DESC → among breaking, newest preferred
	// 3. last_used_today IS NULL DESC     → then unused stories
	// 4. CASE for unused: start_date DESC → among unused, newest preferred
	// 5. last_used_today ASC              → then least-recently-used stories
	// 6. RAND()                           → variety within equal priority
	//
	// Breaking stories consume slots from the limit just like regular stories.
	err := r.db.WithContext(ctx).
		Model(&models.Story{}).
		Select("stories.*, sv.mix_point, "+lastUsedSubquery+" as last_used_today", stationID, todayLocal).
		Joins("JOIN voices v ON stories.voice_id = v.id").
		Joins("JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = stories.voice_id", stationID).
		Where("stories.status = ?", models.StoryStatusActive).
		Where("stories.audio_file IS NOT NULL").
		Where("stories.audio_file != ''").
		Where("stories.start_date <= ?", dateStr).
		Where("stories.end_date >= ?", dateStr).
		Where("stories.weekdays & ? > 0", weekdayBit).
		Order("stories.is_breaking DESC, CASE WHEN stories.is_breaking = 1 THEN stories.start_date END DESC, last_used_today IS NULL DESC, CASE WHEN last_used_today IS NULL THEN stories.start_date END DESC, last_used_today ASC, RAND()").
		Limit(limit).
		Find(&stories).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return stories, nil
}
