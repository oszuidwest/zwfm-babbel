// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// VoiceUpdate contains optional fields for updating a voice.
// Nil pointer fields are not updated.
type VoiceUpdate struct {
	Name *string
}

// VoiceRepository defines the interface for voice data access.
type VoiceRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string) (*models.Voice, error)
	GetByID(ctx context.Context, id int64) (*models.Voice, error)
	Update(ctx context.Context, id int64, updates *VoiceUpdate) error
	Delete(ctx context.Context, id int64) error

	// Query operations
	Exists(ctx context.Context, id int64) (bool, error)
	IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error)
	HasDependencies(ctx context.Context, id int64) (bool, error)

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// voiceRepository implements VoiceRepository.
type voiceRepository struct {
	*BaseRepository[models.Voice]
}

// NewVoiceRepository creates a new voice repository.
func NewVoiceRepository(db *sqlx.DB) VoiceRepository {
	return &voiceRepository{
		BaseRepository: NewBaseRepository[models.Voice](db, "voices"),
	}
}

// Create inserts a new voice and returns the created record.
func (r *voiceRepository) Create(ctx context.Context, name string) (*models.Voice, error) {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "INSERT INTO voices (name) VALUES (?)", name)
	if err != nil {
		return nil, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return r.GetByID(ctx, id)
}

// Update updates an existing voice with type-safe fields.
func (r *voiceRepository) Update(ctx context.Context, id int64, updates *VoiceUpdate) error {
	if updates == nil {
		return nil
	}

	q := r.getQueryable(ctx)

	setClauses := make([]string, 0, 1)
	args := make([]any, 0, 1)

	addFieldUpdate(&setClauses, &args, "name", updates.Name)

	if len(setClauses) == 0 {
		return nil
	}

	query := fmt.Sprintf("UPDATE voices SET %s WHERE id = ?", strings.Join(setClauses, ", "))
	args = append(args, id)

	result, err := q.ExecContext(ctx, query, args...)
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

// IsNameTaken checks if a voice name is already in use.
func (r *voiceRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	condition := "name = ?"
	args := []any{name}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// HasDependencies checks if voice is used by stories or station_voices.
func (r *voiceRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	q := r.getQueryable(ctx)

	var exists bool
	query := `SELECT EXISTS(
		SELECT 1 FROM stories WHERE voice_id = ?
		UNION ALL
		SELECT 1 FROM station_voices WHERE voice_id = ?
	)`
	if err := q.GetContext(ctx, &exists, query, id, id); err != nil {
		return false, ParseDBError(err)
	}

	return exists, nil
}
