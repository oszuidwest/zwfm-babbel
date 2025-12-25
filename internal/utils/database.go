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

func (StationQueries) CountVoices(ctx context.Context, db *sqlx.DB, stationID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ?", stationID)
	return count, err
}

func (StationQueries) CountBulletins(ctx context.Context, db *sqlx.DB, stationID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM bulletins WHERE station_id = ?", stationID)
	return count, err
}

// StoryQueries provides type-safe database operations for stories.
type StoryQueries struct{}

var Stories = StoryQueries{}

func (StoryQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stories WHERE id = ?)", id)
	return exists, err
}

func (StoryQueries) CountByVoice(ctx context.Context, db *sqlx.DB, voiceID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM stories WHERE voice_id = ?", voiceID)
	return count, err
}

func (StoryQueries) CountBulletinStories(ctx context.Context, db *sqlx.DB, storyID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM bulletin_stories WHERE story_id = ?", storyID)
	return count, err
}

// VoiceQueries provides type-safe database operations for voices.
type VoiceQueries struct{}

var Voices = VoiceQueries{}

func (VoiceQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM voices WHERE id = ?)", id)
	return exists, err
}

func (VoiceQueries) CountStationVoices(ctx context.Context, db *sqlx.DB, voiceID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count, "SELECT COUNT(*) FROM station_voices WHERE voice_id = ?", voiceID)
	return count, err
}

// UserQueries provides type-safe database operations for users.
type UserQueries struct{}

var Users = UserQueries{}

func (UserQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", id)
	return exists, err
}

func (UserQueries) CountActiveAdminsExcluding(ctx context.Context, db *sqlx.DB, excludeID int) (int, error) {
	var count int
	err := db.GetContext(ctx, &count,
		"SELECT COUNT(*) FROM users WHERE role = 'admin' AND suspended_at IS NULL AND id != ?", excludeID)
	return count, err
}

func (UserQueries) UsernameExists(ctx context.Context, db *sqlx.DB, username string, excludeID *int) (bool, error) {
	var count int
	var err error
	if excludeID != nil {
		err = db.GetContext(ctx, &count, "SELECT COUNT(*) FROM users WHERE username = ? AND id != ?", username, *excludeID)
	} else {
		err = db.GetContext(ctx, &count, "SELECT COUNT(*) FROM users WHERE username = ?", username)
	}
	return count > 0, err
}

func (UserQueries) EmailExists(ctx context.Context, db *sqlx.DB, email string, excludeID *int) (bool, error) {
	var count int
	var err error
	if excludeID != nil {
		err = db.GetContext(ctx, &count, "SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", email, *excludeID)
	} else {
		err = db.GetContext(ctx, &count, "SELECT COUNT(*) FROM users WHERE email = ?", email)
	}
	return count > 0, err
}

// BulletinQueries provides type-safe database operations for bulletins.
type BulletinQueries struct{}

var Bulletins = BulletinQueries{}

func (BulletinQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM bulletins WHERE id = ?)", id)
	return exists, err
}

// StationVoiceQueries provides type-safe database operations for station-voice relationships.
type StationVoiceQueries struct{}

var StationVoices = StationVoiceQueries{}

func (StationVoiceQueries) Exists(ctx context.Context, db *sqlx.DB, id int) (bool, error) {
	var exists bool
	err := db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM station_voices WHERE id = ?)", id)
	return exists, err
}

func (StationVoiceQueries) CombinationExists(ctx context.Context, db *sqlx.DB, stationID, voiceID int, excludeID *int) (bool, error) {
	var count int
	var err error
	if excludeID != nil {
		err = db.GetContext(ctx, &count,
			"SELECT COUNT(*) FROM station_voices WHERE station_id = ? AND voice_id = ? AND id != ?",
			stationID, voiceID, *excludeID)
	} else {
		err = db.GetContext(ctx, &count,
			"SELECT COUNT(*) FROM station_voices WHERE station_id = ? AND voice_id = ?",
			stationID, voiceID)
	}
	return count > 0, err
}

// =============================================================================
// Legacy function kept for backwards compatibility during migration
// =============================================================================

// CountWithJoins returns the count of records using complex query with joins.
func CountWithJoins(db *sqlx.DB, query string, args ...interface{}) (int64, error) {
	var count int64
	if err := db.Get(&count, query, args...); err != nil {
		return 0, err
	}
	return count, nil
}
