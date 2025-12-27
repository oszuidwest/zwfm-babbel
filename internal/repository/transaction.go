// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// TxManager defines the transaction management interface.
type TxManager interface {
	// WithTransaction executes a function within a transaction.
	// If the function returns an error, the transaction is rolled back.
	// If the function panics, the transaction is rolled back and the panic is re-raised.
	// If the function succeeds, the transaction is committed.
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error

	// WithTransactionOpts allows specifying custom transaction options.
	WithTransactionOpts(ctx context.Context, opts *sql.TxOptions, fn func(ctx context.Context) error) error

	// DB returns the underlying database connection for non-transactional queries.
	DB() *sqlx.DB
}

// txManager implements TxManager using sqlx.
type txManager struct {
	db *sqlx.DB
}

// NewTxManager creates a new transaction manager.
func NewTxManager(db *sqlx.DB) TxManager {
	return &txManager{db: db}
}

// DB returns the underlying database connection.
func (m *txManager) DB() *sqlx.DB {
	return m.db
}

// WithTransaction executes fn within a transaction with default options.
func (m *txManager) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return m.WithTransactionOpts(ctx, nil, fn)
}

// WithTransactionOpts executes fn within a transaction with custom options.
// The transaction is automatically stored in the context and can be retrieved
// by repositories using TxFromContext.
func (m *txManager) WithTransactionOpts(ctx context.Context, opts *sql.TxOptions, fn func(ctx context.Context) error) error {
	tx, err := m.db.BeginTxx(ctx, opts)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Handle panic recovery - rollback and re-panic
	defer func() {
		if p := recover(); p != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
				logger.Error("Failed to rollback transaction after panic: %v", rollbackErr)
			}
			panic(p) // Re-raise the panic
		}
	}()

	// Store transaction in context for repositories to use
	txCtx := ContextWithTx(ctx, tx)

	// Execute the function
	if err := fn(txCtx); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && rollbackErr != sql.ErrTxDone {
			logger.Error("Failed to rollback transaction: %v", rollbackErr)
		}
		return err
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
