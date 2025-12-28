// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"
	"errors"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository/updates"
	"gorm.io/gorm"
)

// VoiceUpdate contains optional fields for updating a voice.
// Nil pointer fields are not updated.
type VoiceUpdate struct {
	Name *string `db:"name"`
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

	if err := r.db.WithContext(ctx).Create(voice).Error; err != nil {
		if IsDuplicateKeyError(err) {
			return nil, ErrDuplicateKey
		}
		return nil, err
	}

	return voice, nil
}

// GetByID retrieves a voice by its ID.
func (r *voiceRepository) GetByID(ctx context.Context, id int64) (*models.Voice, error) {
	var voice models.Voice

	err := r.db.WithContext(ctx).First(&voice, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &voice, nil
}

// Update updates an existing voice with type-safe fields.
func (r *voiceRepository) Update(ctx context.Context, id int64, u *VoiceUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := updates.ToMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.Voice{}).Where("id = ?", id).Updates(updateMap)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete removes a voice by its ID (hard delete since Voice has no soft delete).
func (r *voiceRepository) Delete(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&models.Voice{}, id)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Exists checks if a voice with the given ID exists.
func (r *voiceRepository) Exists(ctx context.Context, id int64) (bool, error) {
	var count int64

	err := r.db.WithContext(ctx).
		Model(&models.Voice{}).
		Where("id = ?", id).
		Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// IsNameTaken checks if a voice name is already in use.
func (r *voiceRepository) IsNameTaken(ctx context.Context, name string, excludeID *int64) (bool, error) {
	var count int64

	query := r.db.WithContext(ctx).
		Model(&models.Voice{}).
		Where("name = ?", name)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	if err := query.Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// HasDependencies checks if voice is used by stories or station_voices.
func (r *voiceRepository) HasDependencies(ctx context.Context, id int64) (bool, error) {
	var storyCount int64
	var stationVoiceCount int64

	// Check stories table
	if err := r.db.WithContext(ctx).
		Model(&models.Story{}).
		Where("voice_id = ?", id).
		Count(&storyCount).Error; err != nil {
		return false, err
	}

	if storyCount > 0 {
		return true, nil
	}

	// Check station_voices table
	if err := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("voice_id = ?", id).
		Count(&stationVoiceCount).Error; err != nil {
		return false, err
	}

	return stationVoiceCount > 0, nil
}
