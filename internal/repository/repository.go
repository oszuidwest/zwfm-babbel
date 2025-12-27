// Package repository provides data access abstractions for the Babbel application.
// It implements the Repository pattern to separate data access concerns from business logic.
package repository

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// Queryable defines the common interface between *sqlx.DB and *sqlx.Tx.
// This allows repositories to work seamlessly with both direct queries and transactions.
type Queryable interface {
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryxContext(ctx context.Context, query string, args ...any) (*sqlx.Rows, error)
	QueryRowxContext(ctx context.Context, query string, args ...any) *sqlx.Row
	Rebind(query string) string
	DriverName() string
}

// Compile-time verification that sqlx.DB and sqlx.Tx implement Queryable
var (
	_ Queryable = (*sqlx.DB)(nil)
	_ Queryable = (*sqlx.Tx)(nil)
)

// txContextKey is the context key for storing transactions
type txContextKey struct{}

// ContextWithTx stores a transaction in the context for use by repositories.
func ContextWithTx(ctx context.Context, tx Queryable) context.Context {
	return context.WithValue(ctx, txContextKey{}, tx)
}

// TxFromContext retrieves a transaction from context, or nil if not present.
func TxFromContext(ctx context.Context) Queryable {
	if tx, ok := ctx.Value(txContextKey{}).(Queryable); ok {
		return tx
	}
	return nil
}
