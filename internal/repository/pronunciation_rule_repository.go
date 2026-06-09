package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// PronunciationRuleRepository reads and replaces global inline-IPA rules.
type PronunciationRuleRepository struct {
	db *gorm.DB
}

// NewPronunciationRuleRepository returns a repository bound to db.
func NewPronunciationRuleRepository(db *gorm.DB) *PronunciationRuleRepository {
	return &PronunciationRuleRepository{db: db}
}

// List returns all pronunciation rules in deterministic editor-facing order.
func (r *PronunciationRuleRepository) List(ctx context.Context) ([]models.PronunciationRule, error) {
	var rules []models.PronunciationRule
	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).
		Order("string_to_replace ASC").
		Find(&rules).Error; err != nil {
		return nil, ParseDBError(err)
	}
	return rules, nil
}

// ReplaceAll atomically replaces every pronunciation rule in the current transaction.
func (r *PronunciationRuleRepository) ReplaceAll(ctx context.Context, rules []models.PronunciationRule) error {
	tx := TxFromContext(ctx)
	if tx == nil {
		return errors.New("replace all pronunciation rules requires an active transaction")
	}

	if err := tx.WithContext(ctx).Exec("DELETE FROM pronunciation_rules").Error; err != nil {
		return ParseDBError(err)
	}
	if len(rules) == 0 {
		return nil
	}
	if err := tx.WithContext(ctx).Create(&rules).Error; err != nil {
		return ParseDBError(err)
	}
	return nil
}

// LockSingletonForWrite serializes pronunciation rule writes through the TTS settings row.
func (r *PronunciationRuleRepository) LockSingletonForWrite(ctx context.Context) error {
	tx := TxFromContext(ctx)
	if tx == nil {
		return errors.New("lock singleton for write requires an active transaction")
	}

	var one int
	result := tx.WithContext(ctx).
		Raw("SELECT 1 FROM tts_settings WHERE id = ? FOR UPDATE", ttsSettingsSingletonID).
		Scan(&one)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 || one != 1 {
		return ErrNotFound
	}
	return nil
}

// MaxUpdatedAt returns the maximum updated_at timestamp, or nil when there are no rules.
func (r *PronunciationRuleRepository) MaxUpdatedAt(ctx context.Context) (*time.Time, error) {
	db := DBFromContext(ctx, r.db)

	var max sql.NullTime
	if err := db.WithContext(ctx).
		Model(&models.PronunciationRule{}).
		Select("MAX(updated_at)").
		Scan(&max).Error; err != nil {
		return nil, ParseDBError(err)
	}
	if !max.Valid {
		return nil, nil
	}
	return &max.Time, nil
}
