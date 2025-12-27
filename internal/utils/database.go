// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// =============================================================================
// Type-safe query structs per entity
// Usage: utils.Stations.Exists(ctx, db, id)
// =============================================================================

// EntityQuerier provides database existence checks for entities.
type EntityQuerier struct {
	tableName string
}

// NewEntityQuerier creates a new EntityQuerier for the given table.
func NewEntityQuerier(tableName string) EntityQuerier {
	return EntityQuerier{tableName: tableName}
}

// Exists checks if an entity with the given ID exists in the table.
func (q EntityQuerier) Exists(ctx context.Context, db *sqlx.DB, id int64) (bool, error) {
	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ?)", q.tableName)
	err := db.GetContext(ctx, &exists, query, id)
	return exists, err
}

// Predefined entity queriers
var (
	Stations  = NewEntityQuerier("stations")
	Stories   = NewEntityQuerier("stories")
	Bulletins = NewEntityQuerier("bulletins")
)

// CountWithJoins returns the count of records using complex query with joins.
func CountWithJoins(db *sqlx.DB, query string, args ...any) (int64, error) {
	var count int64
	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}
	return count, nil
}
