// Package repository provides data access abstractions for the Babbel application.
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

// NewTxManager creates a new transaction manager.
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
	// Use GORM's Transaction method which handles begin, commit, and rollback
	return m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Handle panic recovery - GORM's Transaction already handles rollback on panic,
		// but we need to log it
		defer func() {
			if p := recover(); p != nil {
				logger.Error("Panic in transaction: %v", p)
				panic(p) // Re-raise the panic after logging
			}
		}()

		// Store transaction in context for repositories to use
		txCtx := ContextWithTx(ctx, tx)

		// Execute the function
		if err := fn(txCtx); err != nil {
			return fmt.Errorf("transaction failed: %w", err)
		}

		return nil
	})
}
