// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// BaseRepository provides common CRUD operations for all repositories.
// It uses Go generics to work with any model type.
type BaseRepository[T any] struct {
	db        *sqlx.DB
	tableName string
}

// NewBaseRepository creates a new base repository for the given table.
func NewBaseRepository[T any](db *sqlx.DB, tableName string) *BaseRepository[T] {
	return &BaseRepository[T]{
		db:        db,
		tableName: tableName,
	}
}

// getQueryable returns the transaction from context if present, otherwise the db.
func (r *BaseRepository[T]) getQueryable(ctx context.Context) Queryable {
	if tx := TxFromContext(ctx); tx != nil {
		return tx
	}
	return r.db
}

// DB returns the underlying database connection.
// This is useful for operations that need direct DB access, like ModernListWithQuery.
func (r *BaseRepository[T]) DB() *sqlx.DB {
	return r.db
}

// TableName returns the table name for this repository.
func (r *BaseRepository[T]) TableName() string {
	return r.tableName
}

// GetByID retrieves a record by its ID.
func (r *BaseRepository[T]) GetByID(ctx context.Context, id int64) (*T, error) {
	q := r.getQueryable(ctx)

	var result T
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", r.tableName)

	if err := q.GetContext(ctx, &result, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &result, nil
}

// Exists checks if a record with the given ID exists.
func (r *BaseRepository[T]) Exists(ctx context.Context, id int64) (bool, error) {
	q := r.getQueryable(ctx)

	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ?)", r.tableName)

	if err := q.GetContext(ctx, &exists, query, id); err != nil {
		return false, ParseDBError(err)
	}

	return exists, nil
}

// Count returns the total number of records.
func (r *BaseRepository[T]) Count(ctx context.Context) (int64, error) {
	q := r.getQueryable(ctx)

	var count int64
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s", r.tableName)

	if err := q.GetContext(ctx, &count, query); err != nil {
		return 0, ParseDBError(err)
	}

	return count, nil
}

// Delete performs a hard delete of a record by ID.
func (r *BaseRepository[T]) Delete(ctx context.Context, id int64) error {
	q := r.getQueryable(ctx)

	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", r.tableName)
	result, err := q.ExecContext(ctx, query, id)
	if err != nil {
		return ParseDBError(err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return ParseDBError(err)
	}
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// ExistsBy checks if any record matches the given condition.
// The condition should be a valid SQL WHERE clause fragment (e.g., "name = ? AND status = ?").
func (r *BaseRepository[T]) ExistsBy(ctx context.Context, condition string, args ...interface{}) (bool, error) {
	q := r.getQueryable(ctx)

	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE %s)", r.tableName, condition)

	if err := q.GetContext(ctx, &exists, query, args...); err != nil {
		return false, ParseDBError(err)
	}

	return exists, nil
}

// CountBy counts records matching a condition.
// The condition should be a valid SQL WHERE clause fragment.
func (r *BaseRepository[T]) CountBy(ctx context.Context, condition string, args ...interface{}) (int, error) {
	q := r.getQueryable(ctx)

	var count int
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", r.tableName, condition)

	if err := q.GetContext(ctx, &count, query, args...); err != nil {
		return 0, ParseDBError(err)
	}

	return count, nil
}

// addFieldUpdate adds a field to the update query if the pointer is non-nil.
func addFieldUpdate[T any](setClauses *[]string, args *[]interface{}, column string, value *T) {
	if value == nil {
		return
	}
	*setClauses = append(*setClauses, column+" = ?")
	*args = append(*args, *value)
}
