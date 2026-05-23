package apperrors

import (
	"errors"

	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// Operation represents the type of database operation for FK disambiguation.
type Operation int

const (
	OpQuery Operation = iota
	OpCreate
	OpUpdate
	OpDelete
)

func (o Operation) String() string {
	return [...]string{"query", "create", "update", "delete"}[o]
}

// TranslateRepoError converts repository errors to typed domain errors.
// The resource name and operation provide context for error handling.
// Returns nil if err is nil.
func TranslateRepoError(resource string, op Operation, err error) error {
	if err == nil {
		return nil
	}

	// Repository-level query-shape errors flow through to the handler unchanged
	// so handleServiceError can surface them via ProblemValidationError (422),
	// keeping the response shape and status consistent with parse-time query
	// failures from utils/query.go.
	var unknownField *repository.UnknownFieldError
	if errors.As(err, &unknownField) {
		return err
	}

	var invalidFilter *repository.InvalidFilterError
	if errors.As(err, &invalidFilter) {
		return err
	}

	switch {
	case errors.Is(err, repository.ErrNotFound):
		return NotFoundWithCause(resource, err)

	case errors.Is(err, repository.ErrDuplicateKey):
		return DuplicateWithCause(resource, "", "", err)

	case errors.Is(err, repository.ErrForeignKeyViolation):
		if op == OpDelete {
			return DependencyWithCause(resource, "related resources", err)
		}
		return ValidationWithCause(resource, "reference", "references non-existent resource", err)

	case errors.Is(err, repository.ErrDataTooLong):
		return ValidationWithCause(resource, "field", "exceeds maximum length", err)

	default:
		return Database(resource, op.String(), err)
	}
}
