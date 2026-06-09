package models

import "time"

// PronunciationRule stores one global inline-IPA replacement rule.
type PronunciationRule struct {
	StringToReplace string    `gorm:"primaryKey;column:string_to_replace;size:255;not null"`
	IPA             string    `gorm:"column:ipa;size:255;not null"`
	CaseSensitive   bool      `gorm:"column:case_sensitive;not null"`
	WordBoundaries  bool      `gorm:"column:word_boundaries;not null"`
	CreatedAt       time.Time `gorm:"column:created_at"`
	UpdatedAt       time.Time `gorm:"column:updated_at"`
}

// TableName returns the database table name for PronunciationRule.
func (PronunciationRule) TableName() string {
	return "pronunciation_rules"
}
