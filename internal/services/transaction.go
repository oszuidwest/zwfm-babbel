package services

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// inTransaction runs fn in a transaction. fn translates its own errors, which
// are returned untranslated. A failure to begin or commit the transaction is
// translated for resource and op, so it reports as a DatabaseError.
func inTransaction(ctx context.Context, txManager repository.TxManager, resource string, op apperrors.Operation, fn func(context.Context) error) error {
	var fnErr error
	err := txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		fnErr = fn(txCtx)
		return fnErr
	})
	if fnErr != nil {
		return err
	}
	return apperrors.TranslateRepoError(resource, op, err)
}
