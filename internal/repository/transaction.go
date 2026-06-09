package repository

import (
	"context"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// TxManager defines the transaction management interface.
type TxManager interface {
	// WithTransaction executes a function within a transaction.
	// If the function returns an error, the transaction is rolled back.
	// If the function panics, the transaction is rolled back and the panic is re-raised.
	// If the function succeeds, the transaction is committed.
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error

	// DB returns the underlying GORM database connection for non-transactional queries.
	DB() *gorm.DB
}

// txManager implements TxManager using GORM.
type txManager struct {
	db *gorm.DB
}

// NewTxManager returns a transaction manager backed by db.
func NewTxManager(db *gorm.DB) TxManager {
	return &txManager{db: db}
}

// DB returns the underlying GORM database connection.
func (m *txManager) DB() *gorm.DB {
	return m.db
}

// WithTransaction executes fn within a GORM transaction.
// The transaction is automatically stored in the context and can be retrieved
// by repositories using TxFromContext.
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
