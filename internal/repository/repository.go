// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"gorm.io/gorm"
)

// txContextKey is the context key for storing GORM transactions.
type txContextKey struct{}

// ContextWithTx stores a GORM transaction in the context for use by repositories.
func ContextWithTx(ctx context.Context, tx *gorm.DB) context.Context {
	return context.WithValue(ctx, txContextKey{}, tx)
}

// TxFromContext retrieves a GORM transaction from context, or nil if not present.
func TxFromContext(ctx context.Context) *gorm.DB {
	if tx, ok := ctx.Value(txContextKey{}).(*gorm.DB); ok {
		return tx
	}
	return nil
}

// DBFromContext returns the transaction from context if present, otherwise returns db.
func DBFromContext(ctx context.Context, db *gorm.DB) *gorm.DB {
	if tx := TxFromContext(ctx); tx != nil {
		return tx
	}
	return db
}
