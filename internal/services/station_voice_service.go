// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// StationVoiceService handles business logic for station-voice relationship operations.
// It manages the many-to-many relationship between stations and voices, including
// jingle audio file processing and validation.
type StationVoiceService struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
}

// NewStationVoiceService creates a new station-voice service instance.
func NewStationVoiceService(db *sqlx.DB, audioSvc *audio.Service, cfg *config.Config) *StationVoiceService {
	return &StationVoiceService{
		db:       db,
		audioSvc: audioSvc,
		config:   cfg,
	}
}

// CreateStationVoiceRequest contains the data needed to create a new station-voice relationship.
type CreateStationVoiceRequest struct {
	StationID int
	VoiceID   int
	MixPoint  float64
}

// UpdateStationVoiceRequest contains the data needed to update an existing station-voice relationship.
type UpdateStationVoiceRequest struct {
	StationID *int
	VoiceID   *int
	MixPoint  *float64
}

// Create creates a new station-voice relationship in the database.
// It validates that both station and voice exist and that the combination is unique.
func (s *StationVoiceService) Create(ctx context.Context, req *CreateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Create"

	// Validate station exists
	if err := s.validateStationExists(ctx, req.StationID); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Validate voice exists
	if err := s.validateVoiceExists(ctx, req.VoiceID); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Check uniqueness of station-voice combination
	if err := s.CheckUniqueness(ctx, req.StationID, req.VoiceID, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Insert station-voice relationship
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO station_voices (station_id, voice_id, mix_point) VALUES (?, ?, ?)",
		req.StationID, req.VoiceID, req.MixPoint)
	if err != nil {
		logger.Error("Database error creating station-voice: %v", err)
		return nil, fmt.Errorf("%s: %w", op, s.handleDatabaseError(err))
	}

	stationVoiceID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: failed to get last insert ID", op, ErrDatabaseError)
	}

	// Fetch and return the created station-voice relationship
	return s.GetByID(ctx, int(stationVoiceID))
}

// Update updates an existing station-voice relationship.
// It validates that the station and voice exist (if being updated) and ensures
// the new combination remains unique.
func (s *StationVoiceService) Update(ctx context.Context, id int, req *UpdateStationVoiceRequest) (*models.StationVoice, error) {
	const op = "StationVoiceService.Update"

	// Verify station-voice exists
	current, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Validate station exists if being updated
	if req.StationID != nil {
		if *req.StationID <= 0 {
			return nil, fmt.Errorf("%s: %w: station_id must be positive", op, ErrInvalidInput)
		}
		if err := s.validateStationExists(ctx, *req.StationID); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Validate voice exists if being updated
	if req.VoiceID != nil {
		if *req.VoiceID <= 0 {
			return nil, fmt.Errorf("%s: %w: voice_id must be positive", op, ErrInvalidInput)
		}
		if err := s.validateVoiceExists(ctx, *req.VoiceID); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Validate mix_point range if being updated
	if req.MixPoint != nil {
		if *req.MixPoint < 0 || *req.MixPoint > 300 {
			return nil, fmt.Errorf("%s: %w: mix_point must be between 0 and 300 seconds", op, ErrInvalidInput)
		}
	}

	// Check uniqueness if station_id or voice_id is being updated
	if req.StationID != nil || req.VoiceID != nil {
		// Determine final station and voice IDs
		finalStationID := current.StationID
		finalVoiceID := current.VoiceID

		if req.StationID != nil {
			finalStationID = *req.StationID
		}
		if req.VoiceID != nil {
			finalVoiceID = *req.VoiceID
		}

		// Check uniqueness excluding current record
		if err := s.CheckUniqueness(ctx, finalStationID, finalVoiceID, &id); err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	if req.StationID != nil {
		updates = append(updates, "station_id = ?")
		args = append(args, *req.StationID)
	}

	if req.VoiceID != nil {
		updates = append(updates, "voice_id = ?")
		args = append(args, *req.VoiceID)
	}

	if req.MixPoint != nil {
		updates = append(updates, "mix_point = ?")
		args = append(args, *req.MixPoint)
	}

	if len(updates) == 0 {
		return nil, fmt.Errorf("%s: %w: no fields to update", op, ErrInvalidInput)
	}

	// Execute update
	query := "UPDATE station_voices SET " + strings.Join(updates, ", ") + " WHERE id = ?"
	args = append(args, id)

	if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
		logger.Error("Database error updating station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w", op, s.handleDatabaseError(err))
	}

	// Fetch and return the updated station-voice relationship
	return s.GetByID(ctx, id)
}

// GetByID retrieves a station-voice relationship by its ID with joined station and voice names.
func (s *StationVoiceService) GetByID(ctx context.Context, id int) (*models.StationVoice, error) {
	const op = "StationVoiceService.GetByID"

	var stationVoice models.StationVoice
	query := `SELECT sv.id, sv.station_id, sv.voice_id, sv.audio_file, sv.mix_point,
	                 sv.created_at, sv.updated_at, s.name as station_name, v.name as voice_name
	          FROM station_voices sv
	          JOIN stations s ON sv.station_id = s.id
	          JOIN voices v ON sv.voice_id = v.id
	          WHERE sv.id = ?`

	if err := s.db.GetContext(ctx, &stationVoice, query, id); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d: %v", id, err)
		return nil, fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	return &stationVoice, nil
}

// Delete deletes a station-voice relationship and its associated jingle file if it exists.
// The jingle file is removed from the filesystem after database deletion.
func (s *StationVoiceService) Delete(ctx context.Context, id int) error {
	const op = "StationVoiceService.Delete"

	// Get jingle file and station/voice IDs before deletion
	var record struct {
		AudioFile string `db:"audio_file"`
		StationID int    `db:"station_id"`
		VoiceID   int    `db:"voice_id"`
	}

	err := s.db.GetContext(ctx, &record,
		"SELECT audio_file, station_id, voice_id FROM station_voices WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
		}
		logger.Error("Database error fetching station-voice %d for deletion: %v", id, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	// Delete from database
	result, err := s.db.ExecContext(ctx, "DELETE FROM station_voices WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error deleting station-voice %d: %v", id, err)
		return fmt.Errorf("%s: %w: failed to delete station-voice", op, ErrDatabaseError)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, id)
	}

	// Clean up jingle file if it exists
	if record.AudioFile != "" {
		jinglePath := utils.GetJinglePath(s.config, record.StationID, record.VoiceID)
		if err := os.Remove(jinglePath); err != nil {
			// Log error but don't fail the deletion - database record is already gone
			logger.Error("Failed to remove jingle file %s after deletion: %v", jinglePath, err)
		} else {
			logger.Info("Removed jingle file for station %d voice %d", record.StationID, record.VoiceID)
		}
	}

	return nil
}

// ProcessJingle processes an uploaded jingle audio file for a station-voice relationship.
// The tempPath should be a validated temporary file path from ValidateAndSaveAudioFile.
// This method converts the audio to standardized WAV format (48kHz stereo) and updates the database.
func (s *StationVoiceService) ProcessJingle(ctx context.Context, stationVoiceID int, tempPath string) error {
	const op = "StationVoiceService.ProcessJingle"

	// Get station and voice IDs for the relationship
	var record struct {
		StationID int `db:"station_id"`
		VoiceID   int `db:"voice_id"`
	}

	err := s.db.GetContext(ctx, &record,
		"SELECT station_id, voice_id FROM station_voices WHERE id = ?", stationVoiceID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("%s: %w: station-voice relationship with id %d", op, ErrNotFound, stationVoiceID)
		}
		logger.Error("Database error fetching station-voice %d for jingle processing: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to fetch station-voice", op, ErrDatabaseError)
	}

	// Process jingle with audio service (convert to WAV 48kHz stereo)
	outputPath := utils.GetJinglePath(s.config, record.StationID, record.VoiceID)
	filename, _, err := s.audioSvc.ConvertToWAV(ctx, tempPath, outputPath, 2)
	if err != nil {
		logger.Error("Failed to process jingle audio for station-voice %d: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: jingle conversion failed", op, ErrAudioProcessingFailed)
	}

	// Update database with jingle filename only (not full path)
	filenameOnly := utils.GetJingleFilename(record.StationID, record.VoiceID)
	_, err = s.db.ExecContext(ctx,
		"UPDATE station_voices SET audio_file = ? WHERE id = ?", filenameOnly, stationVoiceID)
	if err != nil {
		// Clean up file on database error
		if rmErr := os.Remove(outputPath); rmErr != nil {
			logger.Error("Failed to remove jingle file after database error: %v", rmErr)
		}
		logger.Error("Failed to update station-voice %d jingle reference: %v", stationVoiceID, err)
		return fmt.Errorf("%s: %w: failed to update jingle reference", op, ErrDatabaseError)
	}

	logger.Info("Processed jingle for station-voice %d: %s", stationVoiceID, filename)
	return nil
}

// CheckUniqueness checks if a station-voice combination is unique.
// The excludeID parameter can be provided to exclude a specific record from the check (for updates).
// Returns ErrDuplicate if the combination already exists.
func (s *StationVoiceService) CheckUniqueness(ctx context.Context, stationID, voiceID int, excludeID *int) error {
	const op = "StationVoiceService.CheckUniqueness"

	var count int
	query := "SELECT COUNT(*) FROM station_voices WHERE station_id = ? AND voice_id = ?"
	args := []interface{}{stationID, voiceID}

	if excludeID != nil {
		query += " AND id != ?"
		args = append(args, *excludeID)
	}

	err := s.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		logger.Error("Database error checking station-voice uniqueness: %v", err)
		return fmt.Errorf("%s: %w: failed to check uniqueness", op, ErrDatabaseError)
	}

	if count > 0 {
		return fmt.Errorf("%s: %w: station-voice combination (station_id=%d, voice_id=%d)", op, ErrDuplicate, stationID, voiceID)
	}

	return nil
}

// validateStationExists checks if a station exists in the database.
func (s *StationVoiceService) validateStationExists(ctx context.Context, stationID int) error {
	const op = "StationVoiceService.validateStationExists"

	var exists bool
	err := s.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM stations WHERE id = ?)", stationID)
	if err != nil {
		logger.Error("Database error checking station existence: %v", err)
		return fmt.Errorf("%s: %w: failed to validate station", op, ErrDatabaseError)
	}
	if !exists {
		return fmt.Errorf("%s: %w: station with id %d not found", op, ErrNotFound, stationID)
	}
	return nil
}

// validateVoiceExists checks if a voice exists in the database.
func (s *StationVoiceService) validateVoiceExists(ctx context.Context, voiceID int) error {
	const op = "StationVoiceService.validateVoiceExists"

	var exists bool
	err := s.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM voices WHERE id = ?)", voiceID)
	if err != nil {
		logger.Error("Database error checking voice existence: %v", err)
		return fmt.Errorf("%s: %w: failed to validate voice", op, ErrDatabaseError)
	}
	if !exists {
		return fmt.Errorf("%s: %w: voice with id %d not found", op, ErrNotFound, voiceID)
	}
	return nil
}

// handleDatabaseError converts database errors to service-level errors.
func (s *StationVoiceService) handleDatabaseError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "Duplicate entry"):
		return fmt.Errorf("%w: station-voice combination already exists", ErrDuplicate)
	case strings.Contains(errStr, "foreign key constraint"):
		return fmt.Errorf("%w: invalid reference to station or voice", ErrInvalidInput)
	case strings.Contains(errStr, "Data too long"):
		return fmt.Errorf("%w: one or more fields exceed maximum length", ErrInvalidInput)
	default:
		return fmt.Errorf("%w: database operation failed", ErrDatabaseError)
	}
}
