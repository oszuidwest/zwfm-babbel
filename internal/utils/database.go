// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"context"

	"github.com/jmoiron/sqlx"
)

// =============================================================================
// Type-safe query structs per entity
// Usage: utils.Stations.Exists(ctx, db, id)
// =============================================================================

// StationQueries provides type-safe database operations for stations.
type StationQueries struct{}

// Stations is the global instance for station queries.
var Stations = StationQueries{}

func (StationQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stations WHERE id = ?)", id)
	return exists, err
}

// StoryQueries provides type-safe database operations for stories.
type StoryQueries struct{}

var Stories = StoryQueries{}

func (StoryQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stories WHERE id = ?)", id)
	return exists, err
}

// BulletinQueries provides type-safe database operations for bulletins.
type BulletinQueries struct{}

var Bulletins = BulletinQueries{}

func (BulletinQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM bulletins WHERE id = ?)", id)
	return exists, err
}

// CountWithJoins returns the count of records using complex query with joins.
func CountWithJoins(db *sqlx.DB, query string, args ...interface{}) (int64, error) {
	var count int64
	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}
	return count, nil
}
