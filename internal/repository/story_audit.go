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
// the before/after difference as one story audit event. Writes that change
// nothing are not recorded, except audio and TTS writes.
func (r *StoryRepository) withAudit(ctx context.Context, id int64, action models.AuditAction, actorUserID *int64, write func(context.Context) error) error {
	return r.inTx(ctx, func(ctx context.Context) error {
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
		changes, err := auditChanges(before, after)
		if err != nil {
			return err
		}
		if changes == nil {
			// New audio overwrites story_{id}.wav, so a publish with the same
			// duration changes no column but still replaces what listeners hear.
			if action != models.AuditActionAudio && action != models.AuditActionTTS {
				return nil
			}
			changes = datatypes.JSON("{}")
		}
		return insertAuditEvents(ctx, []models.AuditEvent{{
			UserID: actorUserID, EntityType: models.AuditEntityStory, EntityID: id, Action: action, Changes: changes,
		}})
	})
}

func (r *StoryRepository) inTx(ctx context.Context, fn func(context.Context) error) error {
	return NewTxManager(DBFromContext(ctx, r.db)).WithTransaction(ctx, fn)
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
		StartDate       models.Date
		EndDate         models.Date
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
		"start_date":       story.StartDate,
		"end_date":         story.EndDate,
		"weekdays":         story.Weekdays,
		"is_breaking":      story.IsBreaking,
		"metadata":         story.Metadata,
		"deleted_at":       story.DeletedAt,
	}, nil
}
