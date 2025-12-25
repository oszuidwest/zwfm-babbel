// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// VoiceService handles voice-related business logic
type VoiceService struct {
	db *sqlx.DB
}

// NewVoiceService creates a new voice service instance
func NewVoiceService(db *sqlx.DB) *VoiceService {
	return &VoiceService{
		db: db,
	}
}

// Create creates a new voice with the given name
func (s *VoiceService) Create(ctx context.Context, name string) (*models.Voice, error) {
	const op = "VoiceService.Create"

	// Check name uniqueness
	if err := s.CheckNameUnique(ctx, name, nil); err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// Create voice
	result, err := s.db.ExecContext(ctx, "INSERT INTO voices (name) VALUES (?)", name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to get last insert id: %w", op, err)
	}

	// Fetch the created voice
	voice, err := s.GetByID(ctx, int(id))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return voice, nil
}

// Update updates an existing voice's name
func (s *VoiceService) Update(ctx context.Context, id int, name string) error {
	const op = "VoiceService.Update"

	// Check if voice exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Check name uniqueness (excluding current record)
	if err := s.CheckNameUnique(ctx, name, &id); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Update voice
	result, err := s.db.ExecContext(ctx, "UPDATE voices SET name = ? WHERE id = ?", name, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// GetByID retrieves a voice by its ID
func (s *VoiceService) GetByID(ctx context.Context, id int) (*models.Voice, error) {
	const op = "VoiceService.GetByID"

	var voice models.Voice
	err := s.db.GetContext(ctx, &voice, "SELECT * FROM voices WHERE id = ?", id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return &voice, nil
}

// Delete deletes a voice after checking for dependencies
func (s *VoiceService) Delete(ctx context.Context, id int) error {
	const op = "VoiceService.Delete"

	// Check if voice exists
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	// Check for dependencies
	hasDeps, err := s.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: voice is used by stories or stations", op, ErrDependencyExists)
	}

	// Delete voice
	result, err := s.db.ExecContext(ctx, "DELETE FROM voices WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	return nil
}

// CheckNameUnique checks if a voice name is unique
// excludeID can be provided to exclude a specific voice from the check (for updates)
func (s *VoiceService) CheckNameUnique(ctx context.Context, name string, excludeID *int) error {
	const op = "VoiceService.CheckNameUnique"

	var count int
	query := "SELECT COUNT(*) FROM voices WHERE name = ?"
	args := []interface{}{name}

	if excludeID != nil {
		query += " AND id != ?"
		args = append(args, *excludeID)
	}

	err := s.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	if count > 0 {
		return fmt.Errorf("%s: %w: voice name '%s'", op, ErrDuplicate, name)
	}

	return nil
}

// HasDependencies checks if a voice has any dependencies (stories or station_voices)
func (s *VoiceService) HasDependencies(ctx context.Context, id int) (bool, error) {
	const op = "VoiceService.HasDependencies"

	// Check stories
	var storyCount int
	err := s.db.GetContext(ctx, &storyCount, "SELECT COUNT(*) FROM stories WHERE voice_id = ?", id)
	if err != nil {
		return false, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	if storyCount > 0 {
		return true, nil
	}

	// Check station_voices
	var stationVoiceCount int
	err = s.db.GetContext(ctx, &stationVoiceCount, "SELECT COUNT(*) FROM station_voices WHERE voice_id = ?", id)
	if err != nil {
		return false, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return stationVoiceCount > 0, nil
}
