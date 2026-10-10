package services

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

// requireExists returns NotFound for resource when exists reports id missing.
// owner names the resource whose operation failed if the lookup itself errors.
func requireExists(ctx context.Context, exists func(context.Context, int64) (bool, error), owner, resource string, id int64) error {
	ok, err := exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError(owner, apperrors.OpQuery, err)
	}
	if !ok {
		return apperrors.NotFoundWithID(resource, id)
	}
	return nil
}
