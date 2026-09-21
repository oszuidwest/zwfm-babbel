package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

const ttsSettingsSingletonID int64 = 1

// TTSSettingsUpdate uses nil for unchanged fields and ClearSeed for an explicit NULL.
type TTSSettingsUpdate struct {
	Stability              *float64 `gorm:"column:stability"`
	ApplyTextNormalization *string  `gorm:"column:apply_text_normalization"`
	Seed                   *uint32  `gorm:"column:seed"`
	TTSStylePrefix         *string  `gorm:"column:tts_style_prefix"`

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

// Update writes non-nil fields without checking RowsAffected, allowing idempotent
// updates. Callers must first verify that the singleton row exists.
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
