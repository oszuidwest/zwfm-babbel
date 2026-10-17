package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// TxManager supplies a transaction context shared by repositories.
type TxManager interface {
	// WithTransaction commits on success and rolls back on error or panic.
	// Panics propagate after rollback.
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type txManager struct {
	db *gorm.DB
}

// NewTxManager returns a transaction manager backed by db.
func NewTxManager(db *gorm.DB) TxManager {
	return &txManager{db: db}
}

func (m *txManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// GORM rolls the transaction back on panic; this defer adds observability
		// before re-raising.
		defer func() {
			if p := recover(); p != nil {
				logger.Error("Panic in transaction", "panic", p)
				panic(p)
			}
		}()

		txCtx := ContextWithTx(ctx, tx)

		if err := fn(txCtx); err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	})
	// When ctx ends, database/sql rolls the transaction back in the
	// background, and a commit that runs after that rollback fails with a bare
	// sql.ErrTxDone. Keep the context error in the chain so callers can tell a
	// canceled or timed-out request from a database failure. Other errors are
	// left alone: a commit that fails on its own stays a database failure,
	// even if ctx ends afterwards.
	if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, sql.ErrTxDone) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}
