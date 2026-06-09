package repository

import (
	"context"
	"database/sql"
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

// ReplaceAll replaces every pronunciation rule, using the caller's transaction when present.
func (r *PronunciationRuleRepository) ReplaceAll(ctx context.Context, rules []models.PronunciationRule) error {
	db := DBFromContext(ctx, r.db)

	if err := db.WithContext(ctx).Exec("DELETE FROM pronunciation_rules").Error; err != nil {
		return ParseDBError(err)
	}
	if len(rules) == 0 {
		return nil
	}
	if err := db.WithContext(ctx).Create(&rules).Error; err != nil {
		return ParseDBError(err)
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
