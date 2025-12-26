package repository

import (
	"errors"
	"fmt"
	"strings"
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

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		return fmt.Errorf("%w: %v", ErrDuplicateKey, err)
	case strings.Contains(errStr, "foreign key constraint"):
		return fmt.Errorf("%w: %v", ErrForeignKeyViolation, err)
	case strings.Contains(errStr, "Data too long"):
		return fmt.Errorf("%w: %v", ErrDataTooLong, err)
	case strings.Contains(errStr, "a]foreign key constraint fails"):
		return fmt.Errorf("%w: %v", ErrForeignKeyViolation, err)
	default:
		return err
	}
}

// IsDuplicateKeyError checks if an error is a duplicate key violation.
func IsDuplicateKeyError(err error) bool {
	return errors.Is(err, ErrDuplicateKey)
}

// IsNotFoundError checks if an error is a not found error.
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// IsForeignKeyError checks if an error is a foreign key violation.
func IsForeignKeyError(err error) bool {
	return errors.Is(err, ErrForeignKeyViolation)
}
