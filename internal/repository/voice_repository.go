package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// VoiceUpdate contains optional fields for updating a voice.
// Nil pointer fields are not updated.
type VoiceUpdate struct {
	Name *string `gorm:"column:name"`
}

// VoiceRepository defines the interface for voice data access.
type VoiceRepository interface {
	// CRUD operations
	Create(ctx context.Context, name string) (*models.Voice, error)
	GetByID(ctx context.Context, id int64) (*models.Voice, error)
	Update(ctx context.Context, id int64, updates *VoiceUpdate) error
	Delete(ctx context.Context, id int64) error

	// List operations
	List(ctx context.Context, query *ListQuery) (*ListResult[models.Voice], error)

	// Query operations
	Exists(ctx context.Context, id int64) (bool, error)
	IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error)
	HasDependencies(ctx context.Context, id int64) (bool, error)
}

// voiceRepository implements VoiceRepository using GORM.
type voiceRepository struct {
	*GormRepository[models.Voice]
}

// NewVoiceRepository creates a new voice repository.
func NewVoiceRepository(db *gorm.DB) VoiceRepository {
	return &voiceRepository{
		GormRepository: NewGormRepository[models.Voice](db),
	}
}

// Create inserts a new voice and returns the created record.
func (r *voiceRepository) Create(ctx context.Context, name string) (*models.Voice, error) {
	voice := &models.Voice{
		Name: name,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(voice).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return voice, nil
}

// GetByID retrieves a voice by its ID.
func (r *voiceRepository) GetByID(ctx context.Context, id int64) (*models.Voice, error) {
	return r.GormRepository.GetByID(ctx, id)
}

// Update updates an existing voice. Nil pointer fields are skipped.
func (r *voiceRepository) Update(ctx context.Context, id int64, u *VoiceUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	return r.UpdateByID(ctx, id, updateMap)
}

// Delete permanently removes a voice by its ID.
func (r *voiceRepository) Delete(ctx context.Context, id int64) error {
	return r.GormRepository.Delete(ctx, id)
}

// Exists reports whether a voice with the given ID exists.
func (r *voiceRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// IsNameTaken reports whether a voice name is already in use.
func (r *voiceRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "name", name, excludeID)
}

// HasDependencies reports whether the voice is used by stories or station_voices.
func (r *voiceRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	return r.HasRelatedRecords(ctx, id, map[string]string{
		"stories":        "voice_id",
		"station_voices": "voice_id",
	})
}

// voiceFieldMapping maps API field names to database columns for voices.
var voiceFieldMapping = FieldMapping{
	"id":         "id",
	"name":       "name",
	"created_at": "created_at",
	"updated_at": "updated_at",
}

// voiceSearchFields defines which fields are searchable for voices.
var voiceSearchFields = []string{"name"}

// List retrieves a paginated list of voices with filtering, sorting, and search.
func (r *voiceRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Voice], error) {
	db := r.db.WithContext(ctx).Model(&models.Voice{})
	return ApplyListQuery[models.Voice](db, query, voiceFieldMapping, voiceSearchFields, []SortField{{Field: "name", Direction: SortAsc}})
}
