package services

import (
	"context"

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
	Name                   *string `json:"name"`
	ElevenLabsVoiceID      *string `json:"elevenlabs_voice_id"`
	ClearElevenLabsVoiceID bool    `json:"clear_elevenlabs_voice_id"`
}

// Create creates a new voice with the given name and optional ElevenLabs voice ID.
func (s *VoiceService) Create(ctx context.Context, name string, elevenLabsVoiceID *string) (*models.Voice, error) {
	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if taken {
		return nil, apperrors.Duplicate("Voice", "name", name)
	}

	// Create voice
	voice, err := s.repo.Create(ctx, name, elevenLabsVoiceID)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpCreate, err)
	}

	return voice, nil
}

// Update updates an existing voice's name and returns the updated voice.
func (s *VoiceService) Update(ctx context.Context, id int64, req *UpdateVoiceRequest) (*models.Voice, error) {
	// Check name uniqueness if name is being updated
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
		}
		if taken {
			return nil, apperrors.Duplicate("Voice", "name", *req.Name)
		}
	}

	// Build type-safe update struct
	updates := &repository.VoiceUpdate{
		Name:                   req.Name,
		ElevenLabsVoiceID:      req.ElevenLabsVoiceID,
		ClearElevenLabsVoiceID: req.ClearElevenLabsVoiceID,
	}

	// Update voice
	if err := s.repo.Update(ctx, id, updates); err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// Delete deletes a voice after checking for dependencies.
func (s *VoiceService) Delete(ctx context.Context, id int64) error {
	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if !exists {
		return apperrors.NotFoundWithID("Voice", id)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if hasDeps {
		return apperrors.Dependency("Voice", "stories or station_voices")
	}

	// Delete voice
	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.TranslateRepoError("Voice", apperrors.OpDelete, err)
	}

	return nil
}

// GetByID retrieves a voice by ID.
func (s *VoiceService) GetByID(ctx context.Context, id int64) (*models.Voice, error) {
	voice, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}

	return voice, nil
}

// List retrieves a paginated list of voices.
func (s *VoiceService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Voice], error) {
	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}

	return result, nil
}
