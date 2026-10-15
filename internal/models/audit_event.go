package models

import (
	"time"

	"gorm.io/datatypes"
)

// AuditEntityType names the kind of record an audit event describes.
type AuditEntityType string

// Audited entity types.
const (
	AuditEntityStory              AuditEntityType = "story"
	AuditEntityTTSSettings        AuditEntityType = "tts_settings"
	AuditEntityPronunciationRules AuditEntityType = "pronunciation_rules"
)

// AuditAction names the change an audit event records.
type AuditAction string

// Audited actions.
const (
	AuditActionCreate  AuditAction = "create"
	AuditActionUpdate  AuditAction = "update"
	AuditActionDelete  AuditAction = "delete"
	AuditActionRestore AuditAction = "restore"
	AuditActionAudio   AuditAction = "audio"
	AuditActionTTS     AuditAction = "tts"
	AuditActionExpire  AuditAction = "expire"
)

// AuditEvent records a committed change and its actor.
type AuditEvent struct {
	ID         int64           `gorm:"primaryKey;autoIncrement" json:"id"`
	OccurredAt time.Time       `gorm:"default:CURRENT_TIMESTAMP(3)" json:"occurred_at"`
	UserID     *int64          `json:"user_id"`
	EntityType AuditEntityType `json:"entity_type"`
	EntityID   int64           `json:"entity_id"`
	Action     AuditAction     `json:"action"`
	Changes    datatypes.JSON  `json:"changes"`
	Username   *string         `gorm:"->;-:migration" json:"username"`
	FullName   *string         `gorm:"->;-:migration" json:"full_name"`
}
