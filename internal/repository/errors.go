// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// Repository-level sentinel errors.
// These are distinct from service errors but can be mapped to them.
var (
	// ErrNotFound indicates the requested record does not exist.
	ErrNotFound = errors.New("record not found")

	// ErrDuplicateKey indicates a unique constraint violation.
	ErrDuplicateKey = errors.New("duplicate key violation")

	// ErrForeignKeyViolation indicates a foreign key constraint violation.
	ErrForeignKeyViolation = errors.New("foreign key violation")

	// ErrDataTooLong indicates data exceeds column capacity.
	ErrDataTooLong = errors.New("data too long for column")
)

// ParseDBError converts database-specific errors to repository errors.
// This provides a consistent error interface across the repository layer.
// Internal error details are logged but not exposed in the returned error
// to prevent database schema leakage to clients.
func ParseDBError(err error) error {
	if err == nil {
		return nil
	}

	// Handle GORM's record not found error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}

	// Handle MySQL-specific errors via type assertion (more robust)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1062: // ER_DUP_ENTRY
			logger.Debug("MySQL duplicate key: %v", err)
			return ErrDuplicateKey
		case 1452: // ER_NO_REFERENCED_ROW_2
			logger.Debug("MySQL foreign key violation: %v", err)
			return ErrForeignKeyViolation
		case 1406: // ER_DATA_TOO_LONG
			logger.Debug("MySQL data too long: %v", err)
			return ErrDataTooLong
		}
	}

	// Fallback to string matching for non-MySQL errors or unhandled cases
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		logger.Debug("Duplicate entry detected: %v", err)
		return ErrDuplicateKey
	case strings.Contains(errStr, "foreign key constraint"):
		logger.Debug("Foreign key constraint violation: %v", err)
		return ErrForeignKeyViolation
	case strings.Contains(errStr, "Data too long"):
		logger.Debug("Data too long for column: %v", err)
		return ErrDataTooLong
	default:
		return err
	}
}
