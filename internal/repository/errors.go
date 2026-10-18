package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// Repository-level sentinel errors returned by data access operations.
var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("record not found")

	// ErrDuplicateKey indicates a unique constraint violation.
	ErrDuplicateKey = errors.New("duplicate key violation")

	// ErrForeignKeyViolation indicates a foreign key constraint violation.
	ErrForeignKeyViolation = errors.New("foreign key violation")

	// ErrDataTooLong indicates data exceeds column capacity.
	ErrDataTooLong = errors.New("data too long for column")

	// ErrSchemaUnavailable indicates a referenced table is missing.
	ErrSchemaUnavailable = errors.New("schema unavailable")

	// ErrAuditSchemaUnavailable indicates the audit_events table is missing.
	// It deliberately does not wrap ErrSchemaUnavailable, so callers whose
	// recovery hint names their own table do not misreport it.
	ErrAuditSchemaUnavailable = errors.New("audit_events table unavailable")
)

// StoryDeletedError indicates a write targeted a soft-deleted story.
type StoryDeletedError struct {
	ID        int64
	DeletedAt time.Time
}

// Error describes the deleted story.
func (e *StoryDeletedError) Error() string {
	return fmt.Sprintf("Story with id %d has been deleted", e.ID)
}

// ParseDBError classifies database-specific errors with repository sentinels
// while preserving the driver's cause and diagnostic text for callers' logs.
// Returns nil if err is nil.
func ParseDBError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}

	if mysqlErr, ok := errors.AsType[*mysql.MySQLError](err); ok {
		switch mysqlErr.Number {
		case 1062: // ER_DUP_ENTRY
			return fmt.Errorf("%w: %w", ErrDuplicateKey, err)
		case 1452: // ER_NO_REFERENCED_ROW_2
			return fmt.Errorf("%w: %w", ErrForeignKeyViolation, err)
		case 1406: // ER_DATA_TOO_LONG
			return fmt.Errorf("%w: %w", ErrDataTooLong, err)
		case 1146: // ER_NO_SUCH_TABLE
			return fmt.Errorf("%w: %w", ErrSchemaUnavailable, err)
		}
	}

	// MySQL 1451 (a delete blocked by a foreign key), SQLite test errors and
	// some wrapped driver errors are classified by their message.
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		return fmt.Errorf("%w: %w", ErrDuplicateKey, err)
	case strings.Contains(errStr, "foreign key constraint"):
		return fmt.Errorf("%w: %w", ErrForeignKeyViolation, err)
	case strings.Contains(errStr, "Data too long"):
		return fmt.Errorf("%w: %w", ErrDataTooLong, err)
	case isTableMissingMessage(errStr):
		return fmt.Errorf("%w: %w", ErrSchemaUnavailable, err)
	default:
		return err
	}
}

func isTableMissingMessage(message string) bool {
	return strings.Contains(message, "no such table:") ||
		(strings.HasPrefix(message, "Table '") && strings.Contains(message, "' doesn't exist"))
}
