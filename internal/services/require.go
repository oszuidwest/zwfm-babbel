package services

import (
	"context"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

// requireExists returns NotFound for resource when exists reports id missing.
func requireExists(ctx context.Context, exists func(context.Context, int64) (bool, error), resource string, id int64) error {
	ok, err := exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError(resource, apperrors.OpQuery, err)
	}
	if !ok {
		return apperrors.NotFoundWithID(resource, id)
	}
	return nil
}

// requireReference returns a 422 for field when the request body references
// an id that does not exist. URL resources use requireExists for a 404.
// owner names the resource being written, for translating lookup failures.
func requireReference(ctx context.Context, exists func(context.Context, int64) (bool, error), owner, field string, id int64) error {
	ok, err := exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError(owner, apperrors.OpQuery, err)
	}
	if !ok {
		return apperrors.Invalid(field, apperrors.CodeNotFound, fmt.Sprintf("no resource with id %d", id))
	}
	return nil
}
