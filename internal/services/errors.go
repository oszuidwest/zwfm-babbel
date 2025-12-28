// Package services provides business logic for the Babbel application.
package services

import (
	"errors"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// MapRepoError translates repository errors to application-level errors.
// It preserves the operation context and maps common repository errors to their
// corresponding application error types.
func MapRepoError(op string, err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	if errors.Is(err, repository.ErrDuplicateKey) {
		return fmt.Errorf("%s: %w", op, apperrors.ErrDuplicate)
	}

	if errors.Is(err, repository.ErrForeignKeyViolation) {
		return fmt.Errorf("%s: %w", op, apperrors.ErrDependencyExists)
	}

	return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
}

// MapRepoErrorWithContext translates repository errors with additional context.
// Use this when you need to include extra information like the resource name or ID.
func MapRepoErrorWithContext(op string, err error, context string) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("%s: %w: %s", op, apperrors.ErrNotFound, context)
	}

	if errors.Is(err, repository.ErrDuplicateKey) {
		return fmt.Errorf("%s: %w: %s", op, apperrors.ErrDuplicate, context)
	}

	if errors.Is(err, repository.ErrForeignKeyViolation) {
		return fmt.Errorf("%s: %w: %s", op, apperrors.ErrDependencyExists, context)
	}

	return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
}

// WrapDBError wraps database errors without mapping, preserving the original error.
// Use this when you want to add context but let the caller handle the mapping.
func WrapDBError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
}

// MustExist is a helper that checks an existence query result and returns
// appropriate errors for the exists/err combination.
func MustExist(op string, exists bool, err error) error {
	if err != nil {
		return WrapDBError(op, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}
	return nil
}
