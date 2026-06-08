package models

import "time"

// TTSSettings stores the singleton ElevenLabs text-to-speech configuration.
type TTSSettings struct {
	ID                        int64     `gorm:"primaryKey;column:id" json:"-"`
	Model                     string    `gorm:"column:model;size:64;not null" json:"model"`
	Stability                 float64   `gorm:"column:stability;not null" json:"stability"`
	SimilarityBoost           float64   `gorm:"column:similarity_boost;not null" json:"similarity_boost"`
	Style                     float64   `gorm:"column:style;not null" json:"style"`
	UseSpeakerBoost           bool      `gorm:"column:use_speaker_boost;not null" json:"use_speaker_boost"`
	Speed                     float64   `gorm:"column:speed;not null" json:"speed"`
	ApplyTextNormalization    string    `gorm:"column:apply_text_normalization;size:8;not null" json:"apply_text_normalization"`
	Seed                      *uint32   `gorm:"column:seed" json:"seed"`
	TTSStylePrefix            string    `gorm:"column:tts_style_prefix;size:500;not null" json:"tts_style_prefix"`
	PronunciationDictionaryID *string   `gorm:"column:pronunciation_dictionary_id;size:255" json:"-"`
	UpdatedAt                 time.Time `gorm:"column:updated_at" json:"updated_at"`
}

// TableName returns the database table name for TTSSettings.
func (TTSSettings) TableName() string {
	return "tts_settings"
}
