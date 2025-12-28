// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// StationVoiceUpdate contains optional fields for updating a station-voice relationship.
// Nil pointer fields are not updated. ClearAudioFile explicitly sets audio_file to NULL.
type StationVoiceUpdate struct {
	StationID      *int64   `gorm:"column:station_id"`
	VoiceID        *int64   `gorm:"column:voice_id"`
	AudioFile      *string  `gorm:"column:audio_file"`
	MixPoint       *float64 `gorm:"column:mix_point"`
	ClearAudioFile bool     // When true, sets audio_file to NULL
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

// Create inserts a new station-voice relationship and returns the created record with joined relations.
func (r *stationVoiceRepository) Create(ctx context.Context, stationID, voiceID int64, mixPoint float64) (*models.StationVoice, error) {
	stationVoice := &models.StationVoice{
		StationID: stationID,
		VoiceID:   voiceID,
		MixPoint:  mixPoint,
	}

	db := DBFromContext(ctx, r.db)
	if err := db.WithContext(ctx).Create(stationVoice).Error; err != nil {
		return nil, ParseDBError(err)
	}

	// Load relations on the created record using Joins (single query with LEFT JOIN)
	if err := db.WithContext(ctx).Joins("Station").Joins("Voice").First(stationVoice, stationVoice.ID).Error; err != nil {
		return nil, ParseDBError(err)
	}

	return stationVoice, nil
}

// GetByID retrieves a station-voice relationship with joined station and voice.
// Uses Joins for efficiency (single query with LEFT JOIN instead of separate queries).
func (r *stationVoiceRepository) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	return r.GetByIDWithJoins(ctx, id, "Station", "Voice")
}

// Update updates a station-voice relationship.
// Uses BuildUpdateMap for automatic nil-pointer and Clear* flag handling.
func (r *stationVoiceRepository) Update(ctx context.Context, id int64, u *StationVoiceUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := BuildUpdateMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	return r.UpdateByID(ctx, id, updateMap)
}

// Delete removes a station-voice relationship.
func (r *stationVoiceRepository) Delete(ctx context.Context, id int64) error {
	return r.GormRepository.Delete(ctx, id)
}

// Exists checks if a station-voice relationship with the given ID exists.
func (r *stationVoiceRepository) Exists(ctx context.Context, id int64) (bool, error) {
	return r.GormRepository.Exists(ctx, id)
}

// IsCombinationTaken checks if a station-voice combination is already in use.
// Uses DBFromContext to support transactions.
func (r *stationVoiceRepository) IsCombinationTaken(ctx context.Context, stationID, voiceID int64, excludeID *int64) (bool, error) {
	var count int64

	db := DBFromContext(ctx, r.db)
	query := db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("station_id = ? AND voice_id = ?", stationID, voiceID)

	if excludeID != nil {
		query = query.Where("id != ?", *excludeID)
	}

	if err := query.Count(&count).Error; err != nil {
		return false, ParseDBError(err)
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
	db := DBFromContext(ctx, r.db)
	result := db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Where("id = ?", id).
		Update("audio_file", audioFile)

	if result.Error != nil {
		return ParseDBError(result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// stationVoiceFieldMapping maps API field names to database columns for filtering/sorting.
// Uses table prefix to avoid ambiguity when using Joins.
var stationVoiceFieldMapping = FieldMapping{
	"id":         "station_voices.id",
	"station_id": "station_voices.station_id",
	"voice_id":   "station_voices.voice_id",
	"mix_point":  "station_voices.mix_point",
	"created_at": "station_voices.created_at",
	"updated_at": "station_voices.updated_at",
}

// List retrieves a paginated list of station-voice relationships with joined relations.
// Uses Joins for efficiency (single query with LEFT JOIN instead of separate queries).
func (r *stationVoiceRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.StationVoice], error) {
	db := r.db.WithContext(ctx).
		Model(&models.StationVoice{}).
		Joins("Station").
		Joins("Voice")

	return ApplyListQuery[models.StationVoice](db, query, stationVoiceFieldMapping, nil, "id ASC")
}
