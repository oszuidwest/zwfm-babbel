// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// StationVoiceUpdate contains optional fields for updating a station-voice relationship.
// Nil pointer fields are not updated.
type StationVoiceUpdate struct {
	StationID *int64   `gorm:"column:station_id"`
	VoiceID   *int64   `gorm:"column:voice_id"`
	AudioFile *string  `gorm:"column:audio_file"`
	MixPoint  *float64 `gorm:"column:mix_point"`
}

// StationVoiceRepository defines the interface for station-voice relationship data access.
type StationVoiceRepository interface {
	// CRUD operations
	Create(ctx context.Context, stationID, voiceID int64, mixPoint float64) (*models.StationVoice, error)
	GetByID(ctx context.Context, id int64) (*models.StationVoice, error)
	Update(ctx context.Context, id int64, updates *StationVoiceUpdate) error
	Delete(ctx context.Context, id int64) error

	// Query operations
	Exists(ctx context.Context, id int64) (bool, error)
	IsCombinationTaken(ctx context.Context, stationID, voiceID int64, excludeID *int64) (bool, error)
	List(ctx context.Context, query *ListQuery) (*ListResult[models.StationVoice], error)

	// Audio operations
	GetStationVoiceIDs(ctx context.Context, id int64) (stationID, voiceID int64, audioFile string, err error)
	UpdateAudio(ctx context.Context, id int64, audioFile string) error
}

// stationVoiceRepository implements StationVoiceRepository using GORM.
type stationVoiceRepository struct {
	*GormRepository[models.StationVoice]
}

// NewStationVoiceRepository creates a new station-voice repository.
func NewStationVoiceRepository(db *gorm.DB) StationVoiceRepository {
	return &stationVoiceRepository{
		GormRepository: NewGormRepository[models.StationVoice](db),
	}
}

// Create inserts a new station-voice relationship and returns the created record.
func (r *stationVoiceRepository) Create(ctx context.Context, stationID, voiceID int64, mixPoint float64) (*models.StationVoice, error) {
	stationVoice := models.StationVoice{
		StationID: stationID,
		VoiceID:   voiceID,
		MixPoint:  mixPoint,
	}

	if err := r.db.WithContext(ctx).Create(&stationVoice).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Fetch the created record with joined station and voice names
	return r.GetByID(ctx, stationVoice.ID)
}

// GetByID retrieves a station-voice relationship with preloaded station and voice.
func (r *stationVoiceRepository) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	var stationVoice models.StationVoice

	err := r.db.WithContext(ctx).
		Preload("Station").
		Preload("Voice").
		First(&stationVoice, id).Error

	if err != nil {
		return nil, ParseDBError(err)
	}

	return &stationVoice, nil
}

// Update updates a station-voice relationship with dynamic fields.
func (r *stationVoiceRepository) Update(ctx context.Context, id int64, u *StationVoiceUpdate) error {
	if u == nil {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.StationVoice{}).Where("id = ?", id).Updates(u)
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete removes a station-voice relationship.
func (r *stationVoiceRepository) Delete(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Delete(&models.StationVoice{}, id)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Exists checks if a station-voice relationship with the given ID exists.
func (r *stationVoiceRepository) Exists(ctx context.Context, id int64) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("id = ?", id).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// IsCombinationTaken checks if a station-voice combination is already in use.
func (r *stationVoiceRepository) IsCombinationTaken(ctx context.Context, stationID, voiceID int64, excludeID *int64) (bool, error) {
	var count int64

	query := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("station_id = ? AND voice_id = ?", stationID, voiceID)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	if err := query.Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// GetStationVoiceIDs retrieves the station_id, voice_id, and audio_file for a station-voice record.
// This is useful for file operations (jingle processing/deletion).
func (r *stationVoiceRepository) GetStationVoiceIDs(ctx context.Context, id int64) (stationID, voiceID int64, audioFile string, err error) {
	var record struct {
		StationID int64  `gorm:"column:station_id"`
		VoiceID   int64  `gorm:"column:voice_id"`
		AudioFile string `gorm:"column:audio_file"`
	}

	err = r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Select("station_id, voice_id, audio_file").
		Where("id = ?", id).
		First(&record).Error

	if err != nil {
		return 0, 0, "", ParseDBError(err)
	}

	return record.StationID, record.VoiceID, record.AudioFile, nil
}

// UpdateAudio updates the audio file reference for a station-voice relationship.
func (r *stationVoiceRepository) UpdateAudio(ctx context.Context, id int64, audioFile string) error {
	result := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("id = ?", id).
		Update("audio_file", audioFile)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// stationVoiceFieldMapping maps API field names to database columns for filtering/sorting.
var stationVoiceFieldMapping = FieldMapping{
	"id":         "id",
	"station_id": "station_id",
	"voice_id":   "voice_id",
	"mix_point":  "mix_point",
	"created_at": "created_at",
	"updated_at": "updated_at",
}

// List retrieves a paginated list of station-voice relationships with preloaded relations.
func (r *stationVoiceRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.StationVoice], error) {
	db := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Preload("Station").
		Preload("Voice")

	return ApplyListQuery[models.StationVoice](db, query, stationVoiceFieldMapping, nil, "id ASC")
}
