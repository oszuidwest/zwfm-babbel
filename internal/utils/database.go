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

// Stations provides query methods for station resources.
var Stations = StationQueries{}

// Exists checks if a station with the given ID exists.
func (StationQueries) Exists(ctx context.Context, db *sqlx.DB, id int64) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stations WHERE id = ?)", id)
	return exists, err
}

// StoryQueries provides type-safe database operations for stories.
type StoryQueries struct{}

// Stories provides query methods for story resources.
var Stories = StoryQueries{}

// Exists checks if a story with the given ID exists.
func (StoryQueries) Exists(ctx context.Context, db *sqlx.DB, id int64) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stories WHERE id = ?)", id)
	return exists, err
}

// BulletinQueries provides type-safe database operations for bulletins.
type BulletinQueries struct{}

// Bulletins provides query methods for bulletin resources.
var Bulletins = BulletinQueries{}

// Exists checks if a bulletin with the given ID exists.
func (BulletinQueries) Exists(ctx context.Context, db *sqlx.DB, id int64) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM bulletins WHERE id = ?)", id)
	return exists, err
}

// CountWithJoins returns the count of records using complex query with joins.
func CountWithJoins(db *sqlx.DB, query string, args ...any) (int64, error) {
	var count int64
	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}
	return count, nil
}
