package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

var errNoAuditTransaction = errors.New("audit event requires a transaction")

// RecordAudit writes only changed fields. The caller must supply a transaction.
func RecordAudit(ctx context.Context, event models.AuditEvent, before, after map[string]any) error {
	if TxFromContext(ctx) == nil {
		return errNoAuditTransaction
	}
	changes, err := auditChanges(before, after)
	if err != nil || changes == nil {
		return err
	}
	event.Changes = changes
	return insertAuditEvents(ctx, []models.AuditEvent{event})
}

// auditChanges returns the fields whose values differ as {"field": {"old", "new"}},
// or nil when nothing changed. JSON comparison handles nullable values and
// metadata without reflecting over models.
func auditChanges(before, after map[string]any) (datatypes.JSON, error) {
	changes := make(map[string]map[string]json.RawMessage)
	fields := make(map[string]any, len(before)+len(after))
	maps.Copy(fields, before)
	maps.Copy(fields, after)
	for field := range fields {
		oldValue, err := json.Marshal(before[field])
		if err != nil {
			return nil, err
		}
		newValue, err := json.Marshal(after[field])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(oldValue, newValue) {
			changes[field] = map[string]json.RawMessage{"old": oldValue, "new": newValue}
		}
	}
	if len(changes) == 0 {
		return nil, nil
	}
	return json.Marshal(changes)
}

// auditInsertBatchSize keeps each INSERT far below MySQL's 65,535 placeholders,
// so a large expiration backlog can still be recorded.
const auditInsertBatchSize = 1000

// insertAuditEvents stores events inside the caller's transaction.
func insertAuditEvents(ctx context.Context, events []models.AuditEvent) error {
	db := TxFromContext(ctx)
	if db == nil {
		return errNoAuditTransaction
	}
	return auditDBError(db.WithContext(ctx).CreateInBatches(&events, auditInsertBatchSize).Error)
}

// auditDBError reports a missing audit_events table with its own sentinel so
// callers do not blame (and suggest recreating) the table they were writing.
// It matches the driver code, not the message: list errors can echo
// user-supplied filter and sort names.
func auditDBError(err error) error {
	if mysqlErr, ok := errors.AsType[*mysql.MySQLError](err); ok && mysqlErr.Number == 1146 { // ER_NO_SUCH_TABLE
		return ErrAuditSchemaUnavailable
	}
	return err
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
	"id":          {Column: "audit_events.id", Type: filterInteger},
	"occurred_at": {Column: "audit_events.occurred_at", Type: filterDateTime},
	"user_id":     {Column: "audit_events.user_id", Type: filterInteger, Nullable: true},
	"entity_type": {Column: "audit_events.entity_type", Type: filterEnum, Enum: []string{string(models.AuditEntityStory), string(models.AuditEntityTTSSettings), string(models.AuditEntityPronunciationRules)}},
	"entity_id":   {Column: "audit_events.entity_id", Type: filterInteger},
	"action": {Column: "audit_events.action", Type: filterEnum, Enum: []string{
		string(models.AuditActionCreate), string(models.AuditActionUpdate), string(models.AuditActionDelete),
		string(models.AuditActionRestore), string(models.AuditActionAudio), string(models.AuditActionTTS),
		string(models.AuditActionExpire),
	}},
}

// List restricts both rows and pagination totals to the allowed entity types.
func (r *AuditEventRepository) List(ctx context.Context, query *ListQuery, entityTypes []string, includeActorNames bool) (*ListResult[models.AuditEvent], error) {
	db := DBFromContext(ctx, r.db).WithContext(ctx).Model(&models.AuditEvent{}).
		Where("audit_events.entity_type IN ?", entityTypes)
	if includeActorNames {
		db = db.Select("audit_events.*, users.username, users.full_name").
			Joins("LEFT JOIN users ON users.id = audit_events.user_id")
	}
	result, err := ApplyListQuery[models.AuditEvent](db, query, auditEventFieldMapping, nil,
		[]SortField{{Field: "occurred_at", Direction: SortDesc}, {Field: "id", Direction: SortDesc}})
	if err != nil {
		return nil, auditDBError(err)
	}
	return result, nil
}
