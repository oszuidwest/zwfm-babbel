package apperrors

import (
	"errors"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// TranslateRepoError converts repository errors to domain errors with operation context.
// Returns nil if err is nil. The operation name is prefixed to provide call-site context.
func TranslateRepoError(op string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, repository.ErrNotFound):
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	case errors.Is(err, repository.ErrDuplicateKey):
		return fmt.Errorf("%s: %w", op, ErrDuplicate)
	case errors.Is(err, repository.ErrForeignKeyViolation):
		return fmt.Errorf("%s: %w", op, ErrDependencyExists)
	case errors.Is(err, repository.ErrDataTooLong):
		return fmt.Errorf("%s: %w", op, ErrDataTooLong)
	default:
		return fmt.Errorf("%s: %w", op, ErrDatabaseError)
	}
}
