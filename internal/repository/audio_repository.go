package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// AudioRepository defines the interface for audio file path lookups.
// This provides a safe way to look up file paths from various tables
// without exposing raw SQL to handlers.
type AudioRepository interface {
	// GetFilePath retrieves a file path from any table by ID.
	// Used by ServeAudio handler for stories, bulletins, and station_voices.
	GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int) (string, error)
}

// audioRepository implements AudioRepository.
type audioRepository struct {
	db *sqlx.DB
}

// NewAudioRepository creates a new audio repository.
func NewAudioRepository(db *sqlx.DB) AudioRepository {
	return &audioRepository{db: db}
}

// allowedTables defines which tables can be queried for audio files.
// This whitelist prevents SQL injection via table/column names.
var allowedTables = map[string]map[string]bool{
	"stories": {
		"audio_file": true,
	},
	"bulletins": {
		"audio_file": true,
	},
	"station_voices": {
		"audio_file": true,
	},
}

// GetFilePath retrieves a file path from the specified table.
// Returns ErrNotFound if the record doesn't exist or has no file.
func (r *audioRepository) GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int) (string, error) {
	// Validate table and column names against whitelist
	tableColumns, ok := allowedTables[tableName]
	if !ok {
		return "", fmt.Errorf("table %s is not allowed for audio lookups", tableName)
	}
	if !tableColumns[fileColumn] {
		return "", fmt.Errorf("column %s is not allowed for table %s", fileColumn, tableName)
	}

	// Validate idColumn (should always be "id" for our use cases)
	if idColumn != "id" {
		return "", fmt.Errorf("id column must be 'id'")
	}

	// Build and execute query - table/column names are now validated
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ?", fileColumn, tableName, idColumn)

	var filePath sql.NullString
	if err := r.db.GetContext(ctx, &filePath, query, id); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNotFound
		}
		return "", ParseDBError(err)
	}

	if !filePath.Valid || filePath.String == "" {
		return "", ErrNotFound
	}

	return filePath.String, nil
}
