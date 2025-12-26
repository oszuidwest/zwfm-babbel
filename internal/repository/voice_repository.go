package repository

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// VoiceRepository defines the interface for voice data access.
type VoiceRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string) (*models.Voice, error)
	GetByID(ctx context.Context, id int) (*models.Voice, error)
	Update(ctx context.Context, id int, name string) error
	Delete(ctx context.Context, id int) error

	// Query operations
	Exists(ctx context.Context, id int) (bool, error)
	IsNameTaken(ctx context.Context, name string, excludeID *int) (bool, error)
	HasDependencies(ctx context.Context, id int) (bool, error)

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

	return r.GetByID(ctx, int(id))
}

// Update updates an existing voice's name.
func (r *voiceRepository) Update(ctx context.Context, id int, name string) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "UPDATE voices SET name = ? WHERE id = ?", name, id)
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
func (r *voiceRepository) IsNameTaken(ctx context.Context, name string, excludeID *int) (bool, error) {
	condition := "name = ?"
	args := []interface{}{name}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// HasDependencies checks if voice is used by stories or station_voices.
func (r *voiceRepository) HasDependencies(ctx context.Context, id int) (bool, error) {
	q := r.getQueryable(ctx)

	// Check stories
	var storyCount int
	if err := q.GetContext(ctx, &storyCount, "SELECT COUNT(*) FROM stories WHERE voice_id = ?", id); err != nil {
		return false, ParseDBError(err)
	}
	if storyCount > 0 {
		return true, nil
	}

	// Check station_voices
	var svCount int
	if err := q.GetContext(ctx, &svCount, "SELECT COUNT(*) FROM station_voices WHERE voice_id = ?", id); err != nil {
		return false, ParseDBError(err)
	}

	return svCount > 0, nil
}
