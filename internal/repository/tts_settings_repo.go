package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

const ttsSettingsSingletonID int64 = 1

// TTSSettingsUpdate contains optional fields for updating the singleton TTS settings.
// Nil pointer fields are not updated. Clear* flags explicitly set fields to NULL.
type TTSSettingsUpdate struct {
	Model                  *string  `gorm:"column:model"`
	Stability              *float64 `gorm:"column:stability"`
	SimilarityBoost        *float64 `gorm:"column:similarity_boost"`
	Style                  *float64 `gorm:"column:style"`
	UseSpeakerBoost        *bool    `gorm:"column:use_speaker_boost"`
	Speed                  *float64 `gorm:"column:speed"`
	ApplyTextNormalization *string  `gorm:"column:apply_text_normalization"`
	Seed                   *int64   `gorm:"column:seed"`
	TTSStylePrefix         *string  `gorm:"column:tts_style_prefix"`

	// Clear flags - when true, explicitly set the field to NULL.
	ClearSeed bool `gorm:"-"`
}

// TTSSettingsRepository provides singleton TTS settings access using GORM.
type TTSSettingsRepository struct {
	db *gorm.DB
}

// NewTTSSettingsRepository creates a new TTS settings repository.
func NewTTSSettingsRepository(db *gorm.DB) *TTSSettingsRepository {
	return &TTSSettingsRepository{db: db}
}

// Get retrieves the singleton TTS settings row.
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

// Update updates the singleton row. RowsAffected==0 is valid for idempotent PATCHes.
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
