package models

import (
	"time"

	"gorm.io/datatypes"
)

// AuditEvent records a committed change and its actor.
type AuditEvent struct {
	ID         int64          `gorm:"primaryKey;autoIncrement" json:"id"`
	OccurredAt time.Time      `gorm:"default:CURRENT_TIMESTAMP(3)" json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	UserID     *int64         `json:"user_id"`
	EntityType string         `json:"entity_type"`
	EntityID   int64          `json:"entity_id"`
	Action     string         `json:"action"`
	Changes    datatypes.JSON `json:"changes"`
	Username   *string        `gorm:"->;-:migration" json:"username"`
	FullName   *string        `gorm:"->;-:migration" json:"full_name"`
}
