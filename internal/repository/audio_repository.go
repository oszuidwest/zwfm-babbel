package repository

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// AudioRepository defines the interface for audio file path lookups.
// This provides a safe way to look up file paths from various tables
// without exposing raw SQL to handlers.
type AudioRepository interface {
	// GetFilePath returns an audio filename from an allowed table/column pair.
	GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int64) (string, error)
}

// audioRepository implements AudioRepository.
type audioRepository struct {
	db *gorm.DB
}

// NewAudioRepository returns an audio repository backed by db.
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

// GetFilePath returns the stored audio filename for id.
// Table and column names must be present in allowedTables because GORM cannot
// parameterize SQL identifiers.
func (r *audioRepository) GetFilePath(ctx context.Context, tableName, fileColumn, idColumn string, id int64) (string, error) {
	tableColumns, ok := allowedTables[tableName]
	if !ok {
		return "", fmt.Errorf("table %s is not allowed for audio lookups", tableName)
	}
	if !tableColumns[fileColumn] {
		return "", fmt.Errorf("column %s is not allowed for table %s", fileColumn, tableName)
	}

	if idColumn != "id" {
		return "", fmt.Errorf("id column must be 'id'")
	}

	var filePath *string
	err := r.db.WithContext(ctx).
		Table(tableName).
		Select(fileColumn).
		Where(idColumn+" = ?", id).
		Scan(&filePath).Error

	if err != nil {
		return "", ParseDBError(err)
	}

	if filePath == nil || *filePath == "" {
		return "", ErrNotFound
	}

	return *filePath, nil
}
