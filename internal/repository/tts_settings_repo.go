package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

const ttsSettingsSingletonID int64 = 1

// TTSSettingsUpdate carries PATCH-style updates for the singleton settings row.
// Nil pointer fields leave columns unchanged. ClearSeed explicitly sets Seed to
// NULL.
type TTSSettingsUpdate struct {
	Stability              *float64 `gorm:"column:stability"`
	SimilarityBoost        *float64 `gorm:"column:similarity_boost"`
	Style                  *float64 `gorm:"column:style"`
	Speed                  *float64 `gorm:"column:speed"`
	ApplyTextNormalization *string  `gorm:"column:apply_text_normalization"`
	Seed                   *uint32  `gorm:"column:seed"`
	TTSStylePrefix         *string  `gorm:"column:tts_style_prefix"`

	// ClearSeed explicitly sets Seed to NULL when true.
	ClearSeed bool `gorm:"-"`
}

// TTSSettingsRepository reads and writes the migration-seeded settings row.
type TTSSettingsRepository struct {
	db *gorm.DB
}

// NewTTSSettingsRepository returns a repository bound to db.
func NewTTSSettingsRepository(db *gorm.DB) *TTSSettingsRepository {
	return &TTSSettingsRepository{db: db}
}

// Get loads the singleton TTS settings row.
func (r *TTSSettingsRepository) Get(ctx context.Context) (*models.TTSSettings, error) {
	var settings models.TTSSettings
	db := DBFromContext(ctx, r.db)
	err := db.WithContext(ctx).
		Where("id = ?", ttsSettingsSingletonID).
		First(&settings).Error
	if err != nil {
		return nil, ParseDBError(err)
	}
	return &settings, nil
}

// Update writes non-nil fields to the migration-seeded singleton row.
// The service checks that id=1 exists before calling Update; this method does not
// inspect RowsAffected so idempotent same-value PATCHes remain successful.
func (r *TTSSettingsRepository) Update(ctx context.Context, u *TTSSettingsUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).
		Model(&models.TTSSettings{}).
		Where("id = ?", ttsSettingsSingletonID).
		Updates(updateMap)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	return nil
}
