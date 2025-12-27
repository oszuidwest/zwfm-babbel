// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// VoiceService handles voice-related business logic
type VoiceService struct {
	repo repository.VoiceRepository
}

// NewVoiceService creates a new voice service instance
func NewVoiceService(repo repository.VoiceRepository) *VoiceService {
	return &VoiceService{
		repo: repo,
	}
}

// Create creates a new voice with the given name
func (s *VoiceService) Create(ctx context.Context, name string) (*models.Voice, error) {
	const op = "VoiceService.Create"

	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: voice name '%s'", op, ErrDuplicate, name)
	}

	// Create voice
	voice, err := s.repo.Create(ctx, name)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: voice name '%s'", op, ErrDuplicate, name)
		}
		return nil, fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return voice, nil
}

// Update updates an existing voice's name
func (s *VoiceService) Update(ctx context.Context, id int64, name string) error {
	const op = "VoiceService.Update"

	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Check name uniqueness (excluding current record)
	taken, err := s.repo.IsNameTaken(ctx, name, &id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if taken {
		return fmt.Errorf("%s: %w: voice name '%s'", op, ErrDuplicate, name)
	}

	// Update voice
	err = s.repo.Update(ctx, id, name)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// Delete deletes a voice after checking for dependencies
func (s *VoiceService) Delete(ctx context.Context, id int64) error {
	const op = "VoiceService.Delete"

	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: voice is used by stories or stations", op, ErrDependencyExists)
	}

	// Delete voice
	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, ErrDatabaseError, err)
	}

	return nil
}

// DB returns the underlying database for ModernListWithQuery.
func (s *VoiceService) DB() *sqlx.DB {
	return s.repo.DB()
}
