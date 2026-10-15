package repository

import (
	"context"
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
	return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
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
}
