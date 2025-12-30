// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// VoiceService handles voice-related business logic.
type VoiceService struct {
	repo repository.VoiceRepository
}

// NewVoiceService creates a new voice service instance.
func NewVoiceService(repo repository.VoiceRepository) *VoiceService {
	return &VoiceService{
		repo: repo,
	}
}

// UpdateVoiceRequest contains the data needed to update an existing voice.
type UpdateVoiceRequest struct {
	Name *string `json:"name"`
}

// Create creates a new voice with the given name.
func (s *VoiceService) Create(ctx context.Context, name string) (*models.Voice, error) {
	const op = "VoiceService.Create"

	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError(op, err)
	}
	if taken {
		return nil, fmt.Errorf("%s: %w: voice name '%s'", op, apperrors.ErrDuplicate, name)
	}

	// Create voice
	voice, err := s.repo.Create(ctx, name)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateKey) {
			return nil, fmt.Errorf("%s: %w: voice name '%s'", op, apperrors.ErrDuplicate, name)
		}
		return nil, apperrors.TranslateRepoError(op, err)
	}

	return voice, nil
}

// Update updates an existing voice's name and returns the updated voice.
func (s *VoiceService) Update(ctx context.Context, id int64, req *UpdateVoiceRequest) (*models.Voice, error) {
	const op = "VoiceService.Update"

	// Check name uniqueness if name is being updated
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return nil, apperrors.TranslateRepoError(op, err)
		}
		if taken {
			return nil, fmt.Errorf("%s: %w: voice name '%s'", op, apperrors.ErrDuplicate, *req.Name)
		}
	}

	// Build type-safe update struct
	updates := &repository.VoiceUpdate{
		Name: req.Name,
	}

	// Update voice
	if err := s.repo.Update(ctx, id, updates); err != nil {
		return nil, apperrors.TranslateRepoError(op, err)
	}

	return s.GetByID(ctx, id)
}

// Delete deletes a voice after checking for dependencies.
func (s *VoiceService) Delete(ctx context.Context, id int64) error {
	const op = "VoiceService.Delete"

	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError(op, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError(op, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: voice is used by stories or stations", op, apperrors.ErrDependencyExists)
	}

	// Delete voice
	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.TranslateRepoError(op, err)
	}

	return nil
}

// GetByID retrieves a voice by ID.
func (s *VoiceService) GetByID(ctx context.Context, id int64) (*models.Voice, error) {
	const op = "VoiceService.GetByID"

	voice, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError(op, err)
	}

	return voice, nil
}

// List retrieves a paginated list of voices.
func (s *VoiceService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Voice], error) {
	const op = "VoiceService.List"

	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError(op, err)
	}

	return result, nil
}
