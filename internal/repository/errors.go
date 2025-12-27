// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
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

	// ErrNoRowsAffected indicates an update/delete affected no rows.
	ErrNoRowsAffected = errors.New("no rows affected")
)

// ParseDBError converts MySQL-specific errors to repository errors.
// This provides a consistent error interface across the repository layer.
func ParseDBError(err error) error {
	if err == nil {
		return nil
	}

	// First, try type assertion for MySQL-specific errors (more robust)
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1062: // ER_DUP_ENTRY
			return fmt.Errorf("%w: %v", ErrDuplicateKey, err)
		case 1452: // ER_NO_REFERENCED_ROW_2
			return fmt.Errorf("%w: %v", ErrForeignKeyViolation, err)
		case 1406: // ER_DATA_TOO_LONG
			return fmt.Errorf("%w: %v", ErrDataTooLong, err)
		}
	}

	// Fallback to string matching for non-MySQL errors or unhandled cases
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		return fmt.Errorf("%w: %v", ErrDuplicateKey, err)
	case strings.Contains(errStr, "foreign key constraint"):
		return fmt.Errorf("%w: %v", ErrForeignKeyViolation, err)
	case strings.Contains(errStr, "Data too long"):
		return fmt.Errorf("%w: %v", ErrDataTooLong, err)
	default:
		return err
	}
}
