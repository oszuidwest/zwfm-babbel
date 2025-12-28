// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// AudioRepository defines the interface for audio file path lookups.
// This provides a safe way to look up file paths from various tables
// without exposing raw SQL to handlers.
type AudioRepository interface {
	// GetFilePath retrieves a file path from any table by ID.
	// Used by ServeAudio handler for stories, bulletins, and station_voices.
	GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int64) (string, error)
}

// audioRepository implements AudioRepository.
type audioRepository struct {
	db *gorm.DB
}

// NewAudioRepository creates a new audio repository.
func NewAudioRepository(db *gorm.DB) AudioRepository {
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
func (r *audioRepository) GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int64) (string, error) {
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

	// Use GORM's raw query with context
	var filePath *string
	err := r.db.WithContext(ctx).
		Table(tableName).
		Select(fileColumn).
		Where(idColumn+" = ?", id).
		Scan(&filePath).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrNotFound
		}
		return "", ParseDBError(err)
	}

	if filePath == nil || *filePath == "" {
		return "", ErrNotFound
	}

	return *filePath, nil
}
