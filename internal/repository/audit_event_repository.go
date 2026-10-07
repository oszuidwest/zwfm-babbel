package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// RecordAudit writes only changed fields. The caller must supply a transaction.
// JSON comparison handles nullable values and metadata without reflecting over models.
func RecordAudit(ctx context.Context, event models.AuditEvent, before, after map[string]any) error {
	db := TxFromContext(ctx)
	if db == nil {
		return errors.New("audit event requires a transaction")
	}
	changes := make(map[string]map[string]json.RawMessage)
	fields := make(map[string]bool, len(before)+len(after))
	for field := range before {
		fields[field] = true
	}
	for field := range after {
		fields[field] = true
	}
	for field := range fields {
		oldValue, err := json.Marshal(before[field])
		if err != nil {
			return err
		}
		newValue, err := json.Marshal(after[field])
		if err != nil {
			return err
		}
		if !bytes.Equal(oldValue, newValue) {
			changes[field] = map[string]json.RawMessage{"old": oldValue, "new": newValue}
		}
	}
	if len(changes) == 0 {
		return nil
	}
	data, err := json.Marshal(changes)
	if err != nil {
		return err
	}
	event.Changes = data
	event.ActorType = "user"
	if event.UserID == nil {
		event.ActorType = "system"
	}
	return ParseDBError(db.WithContext(ctx).Create(&event).Error)
}

// AuditEventRepository reads persistent history, including deleted actors.
type AuditEventRepository struct {
	db *gorm.DB
}

// NewAuditEventRepository returns an audit repository backed by db.
func NewAuditEventRepository(db *gorm.DB) *AuditEventRepository {
	return &AuditEventRepository{db: db}
}

var auditEventFieldMapping = FieldMapping{
	"id":          "audit_events.id",
	"occurred_at": "audit_events.occurred_at",
	"actor_type":  "audit_events.actor_type",
	"user_id":     "audit_events.user_id",
	"entity_type": "audit_events.entity_type",
	"entity_id":   "audit_events.entity_id",
	"action":      "audit_events.action",
}

// List restricts both rows and pagination totals to the allowed entity types.
func (r *AuditEventRepository) List(ctx context.Context, query *ListQuery, entityTypes []string, includeActorNames bool) (*ListResult[models.AuditEvent], error) {
	db := DBFromContext(ctx, r.db).WithContext(ctx).Model(&models.AuditEvent{}).
		Where("audit_events.entity_type IN ?", entityTypes)
	if includeActorNames {
		db = db.Select("audit_events.*, users.username, users.full_name").
			Joins("LEFT JOIN users ON users.id = audit_events.user_id")
	}
	return ApplyListQuery[models.AuditEvent](db, query, auditEventFieldMapping, nil,
		[]SortField{{Field: "occurred_at", Direction: SortDesc}, {Field: "id", Direction: SortDesc}})
}
