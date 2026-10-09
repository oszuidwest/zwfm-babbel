package repository

import (
	"context"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// withAudit runs write in a transaction with the story row locked and records
// the before/after difference as one story audit event.
func (r *StoryRepository) withAudit(ctx context.Context, id int64, action string, actorUserID *int64, write func(context.Context) error) error {
	return NewTxManager(DBFromContext(ctx, r.db)).WithTransaction(ctx, func(ctx context.Context) error {
		db := DBFromContext(ctx, r.db).WithContext(ctx)
		before, err := storyAuditValues(db.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}), id)
		if err != nil {
			return err
		}
		if err := write(ctx); err != nil {
			return err
		}
		after, err := storyAuditValues(db, id)
		if err != nil {
			return err
		}
		return RecordAudit(ctx, models.AuditEvent{
			UserID: actorUserID, EntityType: "story", EntityID: id, Action: action,
		}, before, after)
	})
}

// storyAuditValues reads stored values without Story.AfterFind's HTML decoding
// or computed fields. The anonymous struct carries no gorm.DeletedAt, so deleted
// rows stay visible for restore; scoped writes still reject them with ErrNotFound.
// Nullable columns stay nullable; dates and durations reflect database precision.
func storyAuditValues(db *gorm.DB, id int64) (map[string]any, error) {
	var story struct {
		Title           string
		Text            string
		VoiceID         *int64
		AudioFile       *string
		DurationSeconds *float64
		Status          *string
		StartDate       time.Time
		EndDate         time.Time
		Weekdays        models.Weekdays
		IsBreaking      bool
		Metadata        *datatypes.JSONMap
		DeletedAt       *time.Time
	}
	if err := db.Table("stories").Where("id = ?", id).Take(&story).Error; err != nil {
		return nil, ParseDBError(err)
	}
	return map[string]any{
		"title":            story.Title,
		"text":             story.Text,
		"voice_id":         story.VoiceID,
		"audio_file":       story.AudioFile,
		"duration_seconds": story.DurationSeconds,
		"status":           story.Status,
		"start_date":       story.StartDate.Format("2006-01-02"),
		"end_date":         story.EndDate.Format("2006-01-02"),
		"weekdays":         story.Weekdays,
		"is_breaking":      story.IsBreaking,
		"metadata":         story.Metadata,
		"deleted_at":       story.DeletedAt,
	}, nil
}
