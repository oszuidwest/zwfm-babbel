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
	Model                  *string  `gorm:"column:model"`
	Stability              *float64 `gorm:"column:stability"`
	SimilarityBoost        *float64 `gorm:"column:similarity_boost"`
	Style                  *float64 `gorm:"column:style"`
	UseSpeakerBoost        *bool    `gorm:"column:use_speaker_boost"`
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

// SetPronunciationDictionaryID writes the lazily-created ElevenLabs dictionary
// ID, or NULL when id is nil or empty. MySQL without CLIENT_FOUND_ROWS reports
// 0 affected rows for idempotent same-value writes; the zero-rows branch
// therefore re-queries existence to disambiguate "same value" from "row gone".
func (r *TTSSettingsRepository) SetPronunciationDictionaryID(ctx context.Context, id *string) error {
	var value any
	if id != nil && *id != "" {
		value = *id
	}

	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).
		Model(&models.TTSSettings{}).
		Where("id = ?", ttsSettingsSingletonID).
		Update("pronunciation_dictionary_id", value)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		var count int64
		if err := db.WithContext(ctx).
			Model(&models.TTSSettings{}).
			Where("id = ?", ttsSettingsSingletonID).
			Count(&count).Error; err != nil {
			return ParseDBError(err)
		}
		if count == 0 {
			return ErrNotFound
		}
	}
	return nil
}
