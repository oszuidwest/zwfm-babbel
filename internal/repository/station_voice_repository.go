package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// StationVoiceUpdate contains optional fields for updating a station-voice relationship.
// Nil pointer fields are not updated.
type StationVoiceUpdate struct {
	StationID *int
	VoiceID   *int
	AudioFile *string
	MixPoint  *float64
}

// StationVoiceRepository defines the interface for station-voice relationship data access.
type StationVoiceRepository interface {
	// CRUD operations
	Create(ctx context.Context, stationID, voiceID int, mixPoint float64) (*models.StationVoice, error)
	GetByID(ctx context.Context, id int) (*models.StationVoice, error)
	Update(ctx context.Context, id int, updates *StationVoiceUpdate) error
	Delete(ctx context.Context, id int) error

	// Query operations
	Exists(ctx context.Context, id int) (bool, error)
	IsCombinationTaken(ctx context.Context, stationID, voiceID int, excludeID *int) (bool, error)

	// Audio operations
	GetStationVoiceIDs(ctx context.Context, id int) (stationID, voiceID int, audioFile string, err error)
	UpdateAudio(ctx context.Context, id int, audioFile string) error

	// DB returns the underlying database for ModernListWithQuery
	DB() *sqlx.DB
}

// stationVoiceRepository implements StationVoiceRepository.
type stationVoiceRepository struct {
	*BaseRepository[models.StationVoice]
}

// NewStationVoiceRepository creates a new station-voice repository.
func NewStationVoiceRepository(db *sqlx.DB) StationVoiceRepository {
	return &stationVoiceRepository{
		BaseRepository: NewBaseRepository[models.StationVoice](db, "station_voices"),
	}
}

// Create inserts a new station-voice relationship and returns the created record.
func (r *stationVoiceRepository) Create(ctx context.Context, stationID, voiceID int, mixPoint float64) (*models.StationVoice, error) {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx,
		"INSERT INTO station_voices (station_id, voice_id, mix_point) VALUES (?, ?, ?)",
		stationID, voiceID, mixPoint,
	)
	if err != nil {
		return nil, ParseDBError(err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert id: %w", err)
	}

	return r.GetByID(ctx, int(id))
}

// GetByID retrieves a station-voice relationship with joined station and voice names.
func (r *stationVoiceRepository) GetByID(ctx context.Context, id int) (*models.StationVoice, error) {
	q := r.getQueryable(ctx)

	var stationVoice models.StationVoice
	query := `SELECT sv.id, sv.station_id, sv.voice_id, sv.audio_file, sv.mix_point,
                     sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name
              FROM station_voices sv
              JOIN stations s ON sv.station_id = s.id
              JOIN voices v ON sv.voice_id = v.id
              WHERE sv.id = ?`

	if err := q.GetContext(ctx, &stationVoice, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, ParseDBError(err)
	}

	return &stationVoice, nil
}

// Update updates a station-voice relationship with dynamic fields.
func (r *stationVoiceRepository) Update(ctx context.Context, id int, updates *StationVoiceUpdate) error {
	if updates == nil {
		return nil
	}

	q := r.getQueryable(ctx)

	setClauses := make([]string, 0, 4)
	args := make([]interface{}, 0, 4)

	if updates.StationID != nil {
		setClauses = append(setClauses, "station_id = ?")
		args = append(args, *updates.StationID)
	}
	if updates.VoiceID != nil {
		setClauses = append(setClauses, "voice_id = ?")
		args = append(args, *updates.VoiceID)
	}
	if updates.AudioFile != nil {
		setClauses = append(setClauses, "audio_file = ?")
		args = append(args, *updates.AudioFile)
	}
	if updates.MixPoint != nil {
		setClauses = append(setClauses, "mix_point = ?")
		args = append(args, *updates.MixPoint)
	}

	if len(setClauses) == 0 {
		return nil
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE station_voices SET %s WHERE id = ?", strings.Join(setClauses, ", "))

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

// Delete removes a station-voice relationship.
func (r *stationVoiceRepository) Delete(ctx context.Context, id int) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "DELETE FROM station_voices WHERE id = ?", id)
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

// IsCombinationTaken checks if a station-voice combination is already in use.
func (r *stationVoiceRepository) IsCombinationTaken(ctx context.Context, stationID, voiceID int, excludeID *int) (bool, error) {
	condition := "station_id = ? AND voice_id = ?"
	args := []interface{}{stationID, voiceID}

	if excludeID != nil {
		condition += " AND id != ?"
		args = append(args, *excludeID)
	}

	return r.ExistsBy(ctx, condition, args...)
}

// GetStationVoiceIDs retrieves the station_id, voice_id, and audio_file for a station-voice record.
// This is useful for file operations (jingle processing/deletion).
func (r *stationVoiceRepository) GetStationVoiceIDs(ctx context.Context, id int) (stationID, voiceID int, audioFile string, err error) {
	q := r.getQueryable(ctx)

	var record struct {
		StationID int    `db:"station_id"`
		VoiceID   int    `db:"voice_id"`
		AudioFile string `db:"audio_file"`
	}

	err = q.GetContext(ctx, &record, "SELECT station_id, voice_id, audio_file FROM station_voices WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, "", ErrNotFound
		}
		return 0, 0, "", ParseDBError(err)
	}

	return record.StationID, record.VoiceID, record.AudioFile, nil
}

// UpdateAudio updates the audio file reference for a station-voice relationship.
func (r *stationVoiceRepository) UpdateAudio(ctx context.Context, id int, audioFile string) error {
	q := r.getQueryable(ctx)

	result, err := q.ExecContext(ctx, "UPDATE station_voices SET audio_file = ? WHERE id = ?", audioFile, id)
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
