package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// VoiceUpdate contains optional fields for updating a voice.
// Nil pointers leave fields unchanged; ClearElevenLabsVoiceID sets the ID to NULL.
type VoiceUpdate struct {
	Name                   *string `gorm:"column:name"`
	ElevenLabsVoiceID      *string `gorm:"column:elevenlabs_voice_id"`
	ClearElevenLabsVoiceID bool    `gorm:"-"`
}

// VoiceRepository provides voice data access using GORM.
type VoiceRepository struct {
	*GormRepository[models.Voice]
}

// NewVoiceRepository creates a new voice repository.
func NewVoiceRepository(db *gorm.DB) *VoiceRepository {
	return &VoiceRepository{
		GormRepository: NewGormRepository[models.Voice](db),
	}
}

// Create inserts a new voice and returns the created record.
func (r *VoiceRepository) Create(ctx context.Context, name string, elevenLabsVoiceID *string) (*models.Voice, error) {
	voice := &models.Voice{
		Name:              name,
		ElevenLabsVoiceID: elevenLabsVoiceID,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(voice).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return voice, nil
}

// Update applies the fields and clearing flag in u.
func (r *VoiceRepository) Update(ctx context.Context, id int64, u *VoiceUpdate) error {
	return updateFields(ctx, id, u, r.UpdateByID)
}

// IsNameTaken reports whether a voice name is already in use.
func (r *VoiceRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	return r.IsFieldValueTaken(ctx, "name", name, excludeID)
}

// HasDependencies reports whether the voice is used by stories or station_voices.
func (r *VoiceRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	return r.HasRelatedRecords(ctx, id, map[string]string{
		"stories":        "voice_id",
		"station_voices": "voice_id",
	})
}

var voiceFieldMapping = FieldMapping{
	"id":                  {Column: "id", Type: filterInteger},
	"name":                {Column: "name", Type: filterString},
	"elevenlabs_voice_id": {Column: "elevenlabs_voice_id", Type: filterString, Nullable: true},
	"created_at":          {Column: "created_at", Type: filterDateTime},
	"updated_at":          {Column: "updated_at", Type: filterDateTime},
}

var voiceSearchFields = []string{"name"}

// List retrieves a paginated list of voices with filtering, sorting, and search.
func (r *VoiceRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.Voice], error) {
	db := r.db.WithContext(ctx).Model(&models.Voice{})
	return ApplyListQuery[models.Voice](db, query, voiceFieldMapping, voiceSearchFields, []SortField{{Field: "name", Direction: SortAsc}})
}
