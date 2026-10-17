package repository

import (
	"context"
	"errors"
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

	Title          string
	Text           string
	VoiceID        *int64
	Status         string
	StartDate      time.Time
	EndDate        time.Time
	Weekdays       models.Weekdays
	IsBreaking     bool
	Metadata       *datatypes.JSONMap
	IdempotencyKey *string
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

// Create inserts a story; an idempotency key already in use fails with ErrDuplicateKey.
func (r *StoryRepository) Create(ctx context.Context, data *StoryCreateData) (*models.Story, error) {
	story := &models.Story{
		Title:          data.Title,
		Text:           data.Text,
		VoiceID:        data.VoiceID,
		Status:         models.StoryStatus(data.Status),
		StartDate:      models.Date(data.StartDate),
		EndDate:        models.Date(data.EndDate),
		Weekdays:       data.Weekdays,
		IsBreaking:     data.IsBreaking,
		Metadata:       data.Metadata,
		IdempotencyKey: data.IdempotencyKey,
	}

	err := r.inTx(ctx, func(ctx context.Context) error {
		db := DBFromContext(ctx, r.db).WithContext(ctx)
		if err := db.Create(story).Error; err != nil {
			return ParseDBError(err)
		}
		values, err := storyAuditValues(db, story.ID)
		if err != nil {
			return err
		}
		return RecordAudit(ctx, models.AuditEvent{
			UserID: data.ActorUserID, EntityType: models.AuditEntityStory, EntityID: story.ID, Action: models.AuditActionCreate,
		}, nil, values)
	})
	if err != nil {
		return nil, err
	}
	return story, nil
}

// GetIDByIdempotencyKey returns the ID of the story created with key, deleted
// stories included, or ErrNotFound.
func (r *StoryRepository) GetIDByIdempotencyKey(ctx context.Context, key string) (int64, error) {
	var story models.Story
	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Unscoped().Select("id").Where("idempotency_key = ?", key).Take(&story).Error; err != nil {
		return 0, ParseDBError(err)
	}
	return story.ID, nil
}

// GetByID loads a story with its associated voice.
func (r *StoryRepository) GetByID(ctx context.Context, id int64) (*models.Story, error) {
	return r.GetByIDWithPreload(ctx, id, "Voice")
}

// GetByIDForWrite loads a story with its voice before a write, distinguishing deleted rows.
func (r *StoryRepository) GetByIDForWrite(ctx context.Context, id int64) (*models.Story, error) {
	story, err := r.GetByID(ctx, id)
	return story, r.classifyWriteError(ctx, id, err)
}

// UpdateByID reports writes to deleted stories as StoryDeletedError.
func (r *StoryRepository) UpdateByID(ctx context.Context, id int64, updates any) error {
	return r.classifyWriteError(ctx, id, r.GormRepository.UpdateByID(ctx, id, updates))
}

// classifyWriteError checks deletion only after a scoped operation misses.
func (r *StoryRepository) classifyWriteError(ctx context.Context, id int64, err error) error {
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	var story models.Story
	db := DBFromContext(ctx, r.db)
	if lookupErr := db.WithContext(ctx).Unscoped().Select("deleted_at").First(&story, id).Error; lookupErr != nil {
		return ParseDBError(lookupErr)
	}
	if story.DeletedAt.Valid {
		return &StoryDeletedError{ID: id, DeletedAt: story.DeletedAt.Time}
	}
	return err
}

// Update applies non-nil story fields.
func (r *StoryRepository) Update(ctx context.Context, id int64, u *StoryUpdate) error {
	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}
	return r.withAudit(ctx, id, models.AuditActionUpdate, u.ActorUserID, func(ctx context.Context) error {
		return r.UpdateByID(ctx, id, updateMap)
	})
}

// SoftDelete marks a story as deleted without removing it from the database.
func (r *StoryRepository) SoftDelete(ctx context.Context, id int64, actorUserID *int64) error {
	return r.withAudit(ctx, id, models.AuditActionDelete, actorUserID, func(ctx context.Context) error {
		err := r.classifyWriteError(ctx, id, r.Delete(ctx, id))
		if _, ok := errors.AsType[*StoryDeletedError](err); ok {
			return nil
		}
		return err
	})
}

// Restore clears the deleted_at timestamp.
func (r *StoryRepository) Restore(ctx context.Context, id int64, actorUserID *int64) error {
	return r.withAudit(ctx, id, models.AuditActionRestore, actorUserID, func(ctx context.Context) error {
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

// StoryAudioUpdate describes newly processed story audio. Action records
// whether it was uploaded or generated.
type StoryAudioUpdate struct {
	ActorUserID *int64
	Action      models.AuditAction

	AudioFile       string
	DurationSeconds float64
}

// UpdateAudio updates the row and records the audit event atomically. Inside
// a caller's transaction the row stays locked until that transaction commits,
// so the caller can publish the file before commit in row-lock order.
func (r *StoryRepository) UpdateAudio(ctx context.Context, id int64, u StoryAudioUpdate) error {
	return r.withAudit(ctx, id, u.Action, u.ActorUserID, func(ctx context.Context) error {
		return r.UpdateByID(ctx, id, map[string]any{
			"audio_file":       u.AudioFile,
			"duration_seconds": u.DurationSeconds,
		})
	})
}

// ExpireStoriesPastEndDate marks active stories whose end_date has passed as
// expired and returns the number of stories updated.
// GORM automatically excludes soft-deleted records (deleted_at IS NULL).
func (r *StoryRepository) ExpireStoriesPastEndDate(ctx context.Context) (int64, error) {
	var count int64
	err := r.inTx(ctx, func(ctx context.Context) error {
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
		if err := db.Model(&models.Story{}).Where("id IN ?", ids).Update("status", models.StoryStatusExpired).Error; err != nil {
			return ParseDBError(err)
		}
		changes, err := auditChanges(map[string]any{"status": models.StoryStatusActive},
			map[string]any{"status": models.StoryStatusExpired})
		if err != nil {
			return err
		}
		events := make([]models.AuditEvent, len(ids))
		for i, id := range ids {
			events[i] = models.AuditEvent{
				EntityType: models.AuditEntityStory, EntityID: id, Action: models.AuditActionExpire, Changes: changes,
			}
		}
		if err := insertAuditEvents(ctx, events); err != nil {
			return err
		}
		count = int64(len(ids))
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

var storyFieldMapping = FieldMapping{
	"id":               {Column: "id", Type: filterInteger},
	"title":            {Column: "title", Type: filterString},
	"text":             {Column: "text", Type: filterString},
	"voice_id":         {Column: "voice_id", Type: filterInteger, Nullable: true},
	"audio_url":        {Column: "audio_file", Type: filterString},
	"has_audio":        {Column: "(COALESCE(audio_file, '') != '')", Type: filterPresence},
	"status":           {Column: "status", Type: filterEnum, Enum: []string{string(models.StoryStatusDraft), string(models.StoryStatusActive), string(models.StoryStatusExpired)}},
	"start_date":       {Column: "start_date", Type: filterDate},
	"end_date":         {Column: "end_date", Type: filterDate},
	"duration_seconds": {Column: "duration_seconds", Type: filterNumber, Nullable: true},
	"weekdays":         {Column: "weekdays", Type: filterBitmask},
	"is_breaking":      {Column: "is_breaking", Type: filterBoolean},
	"created_at":       {Column: "created_at", Type: filterDateTime},
	"updated_at":       {Column: "updated_at", Type: filterDateTime},
	"deleted_at":       {Column: "deleted_at", Type: filterDateTime, Nullable: true},
}

var storySearchFields = []string{"title", "text"}

// List retrieves stories with filtering, sorting, and pagination.
// query.Trashed controls inclusion of soft-deleted stories.
func (r *StoryRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Story], error) {
	db := r.db.WithContext(ctx).Model(&models.Story{}).Preload("Voice")
	db = ApplySoftDeleteFilter(db, query.Trashed)

	return ApplyListQuery[models.Story](db, query, storyFieldMapping, storySearchFields, []SortField{{Field: "created_at", Direction: SortDesc}})
}

// BulletinStoryData contains story data with station-specific mix point for audio processing.
type BulletinStoryData struct {
	models.Story
	MixPoint float64 `gorm:"column:mix_point"`
}

// GetStoriesForBulletin selects up to limit stories with station-specific mix points.
// Eligible stories are active, have audio and a voice linked to the station,
// and are scheduled for date and its weekday.
//
// Breaking stories take priority, then unused stories, then least recently used.
// Breaking and unused stories prefer newer start dates; remaining ties are random.
// Usage is tracked per station from midnight in date's location.
//
// Breaking stories count toward limit. The caller determines playback order.
func (r *StoryRepository) GetStoriesForBulletin(ctx context.Context, stationID int64, date time.Time, limit int) ([]BulletinStoryData, error) {
	var stories []BulletinStoryData

	// time.Weekday is always in range [0,6], safe to convert to uint8.
	weekdayBit := 1 << uint8(date.Weekday()) // #nosec G115

	todayLocal := startOfDay(date)

	// A date string avoids timezone conversion in MySQL DATE comparisons.
	dateStr := date.Format(time.DateOnly)

	// NULL marks stories unused by this station since local midnight.
	lastUsedSubquery := `(
		SELECT MAX(b.created_at)
		FROM bulletin_stories bs
		JOIN bulletins b ON bs.bulletin_id = b.id
		WHERE bs.story_id = stories.id
		  AND b.station_id = ?
		  AND b.created_at >= ?
	)`

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
