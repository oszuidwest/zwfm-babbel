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
	// GetFilePath returns the stored audio filename from an allowed table, or
	// ErrNotFound when the row has no servable audio.
	GetFilePath(ctx context.Context, tableName string, id int64) (string, error)
}

// audioRepository implements AudioRepository.
type audioRepository struct {
	db *gorm.DB
}

// NewAudioRepository returns an audio repository backed by db.
func NewAudioRepository(db *gorm.DB) AudioRepository {
	return &audioRepository{db: db}
}

// allowedTables defines which tables can be queried for audio files and the
// extra condition under which a row's audio is still served. This whitelist
// prevents SQL injection via table names; every audio-bearing table stores its
// filename in the audio_file column keyed by id.
var allowedTables = map[string]string{
	"stories":        "",                       // Soft-deleted stories keep trash previews.
	"bulletins":      "file_purged_at IS NULL", // A purge keeps audio_file.
	"station_voices": "",
}

// GetFilePath returns the stored audio filename for id.
// The table name must be present in allowedTables because GORM cannot
// parameterize SQL identifiers.
func (r *audioRepository) GetFilePath(ctx context.Context, tableName string, id int64) (string, error) {
	scope, ok := allowedTables[tableName]
	if !ok {
		return "", fmt.Errorf("table %s is not allowed for audio lookups", tableName)
	}

	var filePath *string
	query := r.db.WithContext(ctx).
		Table(tableName).
		Select("audio_file").
		Where("id = ?", id)
	if scope != "" {
		query = query.Where(scope)
	}
	err := query.Scan(&filePath).Error

	if err != nil {
		return "", ParseDBError(err)
	}

	if filePath == nil || *filePath == "" {
		return "", ErrNotFound
	}

	return *filePath, nil
}
