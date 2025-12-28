// Package repository provides data access abstractions for the Babbel application.
package repository

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository/updates"
	"gorm.io/gorm"
)

// StationVoiceUpdate contains optional fields for updating a station-voice relationship.
// Nil pointer fields are not updated.
type StationVoiceUpdate struct {
	StationID *int64   `db:"station_id"`
	VoiceID   *int64   `db:"voice_id"`
	AudioFile *string  `db:"audio_file"`
	MixPoint  *float64 `db:"mix_point"`
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

// GetByID retrieves a station-voice relationship with joined station and voice names.
func (r *stationVoiceRepository) GetByID(ctx context.Context, id int64) (*models.StationVoice, error) {
	var stationVoice models.StationVoice

	// Use a raw query with joins to populate the virtual fields
	err := r.db.WithContext(ctx).
		Table("station_voices sv").
		Select("sv.id, sv.station_id, sv.voice_id, sv.audio_file, sv.mix_point, sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name").
		Joins("JOIN stations s ON sv.station_id = s.id").
		Joins("JOIN voices v ON sv.voice_id = v.id").
		Where("sv.id = ?", id).
		Scan(&stationVoice).Error

	if err != nil {
		return nil, err
	}

	// Check if record was found (Scan doesn't return ErrRecordNotFound)
	if stationVoice.ID == 0 {
		return nil, ErrNotFound
	}

	return &stationVoice, nil
}

// Update updates a station-voice relationship with dynamic fields.
func (r *stationVoiceRepository) Update(ctx context.Context, id int64, u *StationVoiceUpdate) error {
	if u == nil {
		return nil
	}

	updateMap := updates.ToMap(u)
	if len(updateMap) == 0 {
		return nil
	}

	result := r.db.WithContext(ctx).Model(&models.StationVoice{}).Where("id = ?", id).Updates(updateMap)
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
var stationVoiceFieldMapping = map[string]string{
	"id":         "station_voices.id",
	"station_id": "station_voices.station_id",
	"voice_id":   "station_voices.voice_id",
	"mix_point":  "station_voices.mix_point",
	"created_at": "station_voices.created_at",
	"updated_at": "station_voices.updated_at",
}

// List retrieves a paginated list of station-voice relationships with joined station and voice names.
func (r *stationVoiceRepository) List(ctx context.Context, query *ListQuery) (*ListResult[models.StationVoice], error) {
	if query == nil {
		query = NewListQuery()
	}

	// Build base query with joins for station and voice names
	baseQuery := r.db.WithContext(ctx).
		Table("station_voices").
		Select("station_voices.*, stations.name as station_name, voices.name as voice_name").
		Joins("LEFT JOIN stations ON stations.id = station_voices.station_id").
		Joins("LEFT JOIN voices ON voices.id = station_voices.voice_id")

	// Apply filters
	for _, filter := range query.Filters {
		dbField, ok := stationVoiceFieldMapping[filter.Field]
		if !ok {
			continue // Skip unknown fields for security
		}

		switch filter.Operator {
		case FilterEquals:
			baseQuery = baseQuery.Where(dbField+" = ?", filter.Value)
		case FilterNotEquals:
			baseQuery = baseQuery.Where(dbField+" != ?", filter.Value)
		case FilterGreaterThan:
			baseQuery = baseQuery.Where(dbField+" > ?", filter.Value)
		case FilterGreaterOrEq:
			baseQuery = baseQuery.Where(dbField+" >= ?", filter.Value)
		case FilterLessThan:
			baseQuery = baseQuery.Where(dbField+" < ?", filter.Value)
		case FilterLessOrEq:
			baseQuery = baseQuery.Where(dbField+" <= ?", filter.Value)
		case FilterLike:
			baseQuery = baseQuery.Where(dbField+" LIKE ?", filter.Value)
		case FilterIn:
			baseQuery = baseQuery.Where(dbField+" IN ?", filter.Value)
		}
	}

	// Count total before pagination
	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	// Apply sorting
	if len(query.Sort) > 0 {
		for _, sort := range query.Sort {
			dbField, ok := stationVoiceFieldMapping[sort.Field]
			if !ok {
				continue // Skip unknown fields for security
			}
			direction := "ASC"
			if sort.Direction == SortDesc {
				direction = "DESC"
			}
			baseQuery = baseQuery.Order(dbField + " " + direction)
		}
	} else {
		baseQuery = baseQuery.Order("station_voices.id ASC")
	}

	// Apply pagination
	baseQuery = baseQuery.Offset(query.Offset).Limit(query.Limit)

	// Execute query
	var results []models.StationVoice
	if err := baseQuery.Find(&results).Error; err != nil {
		return nil, err
	}

	return &ListResult[models.StationVoice]{
		Data:   results,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}
