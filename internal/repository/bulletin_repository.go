// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// BulletinRepository defines the interface for bulletin data access.
type BulletinRepository interface {
	// CRUD operations
	Create(ctx context.Context, stationID int64, filename, audioFile string, duration float64, fileSize int64, storyCount int) (int64, error)
	GetByID(ctx context.Context, id int64) (*models.Bulletin, error)

	// Query operations
	GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error)

	// Story linking
	LinkStories(ctx context.Context, bulletinID int64, storyIDs []int64) error

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// bulletinRepository implements BulletinRepository.
type bulletinRepository struct {
	*BaseRepository[models.Bulletin]
}

// NewBulletinRepository creates a new bulletin repository.
func NewBulletinRepository(db *sqlx.DB) BulletinRepository {
	return &bulletinRepository{
		BaseRepository: NewBaseRepository[models.Bulletin](db, "bulletins"),
	}
}

// Create inserts a new bulletin and returns the created ID.
func (r *bulletinRepository) Create(ctx context.Context, stationID int64, filename, audioFile string, duration float64, fileSize int64, storyCount int) (int64, error) {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		`INSERT INTO bulletins (station_id, filename, audio_file, duration_seconds, file_size, story_count)
		VALUES (?, ?, ?, ?, ?, ?)`,
		stationID, filename, audioFile, duration, fileSize, storyCount,
	)
	if err != nil {
		return 0, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return id, nil
}

// GetByID retrieves a bulletin by ID with station name.
func (r *bulletinRepository) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	q := r.getQueryable(ctx)

	var bulletin models.Bulletin
	query := `SELECT b.*, s.name as station_name
              FROM bulletins b
              JOIN stations s ON b.station_id = s.id
              WHERE b.id = ?`

	if err := q.GetContext(ctx, &bulletin, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (r *bulletinRepository) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	q := r.getQueryable(ctx)

	var bulletin models.Bulletin

	query := `SELECT b.*, s.name as station_name
              FROM bulletins b
              JOIN stations s ON b.station_id = s.id
              WHERE b.station_id = ?`

	args := []any{stationID}

	if maxAge != nil {
		query += ` AND b.created_at >= ?`
		args = append(args, time.Now().Add(-*maxAge))
	}

	query += ` ORDER BY b.created_at DESC LIMIT 1`

	if err := q.GetContext(ctx, &bulletin, query, args...); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &bulletin, nil
}

// LinkStories creates bulletin-story relationship records using batch INSERT.
func (r *bulletinRepository) LinkStories(ctx context.Context, bulletinID int64, storyIDs []int64) error {
	if len(storyIDs) == 0 {
		return nil
	}

	q := r.getQueryable(ctx)

	// Build batch INSERT for all stories
	valueStrings := make([]string, 0, len(storyIDs))
	valueArgs := make([]any, 0, len(storyIDs)*3)
	for i, storyID := range storyIDs {
		valueStrings = append(valueStrings, "(?, ?, ?)")
		valueArgs = append(valueArgs, bulletinID, storyID, i)
	}

	query := fmt.Sprintf("INSERT INTO bulletin_stories (bulletin_id, story_id, story_order) VALUES %s", strings.Join(valueStrings, ", "))
	_, err := q.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		return ParseDBError(err)
	}

	return nil
}
