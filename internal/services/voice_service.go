package services

import (
	"context"
	"regexp"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// elevenLabsVoiceIDPattern matches the alphanumeric voice IDs ElevenLabs issues
// (e.g. 21m00Tcm4TlvDq8ikWAM). Hyphen and underscore are allowed for
// forward-compatibility, but path-altering characters are rejected so the value
// can never reshape the upstream URL.
var elevenLabsVoiceIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

func validateElevenLabsVoiceID(id *string) error {
	if id == nil || *id == "" {
		return nil
	}
	if !elevenLabsVoiceIDPattern.MatchString(*id) {
		return apperrors.Validation("Voice", "elevenlabs_voice_id",
			"must be 8-64 characters of letters, digits, hyphen, or underscore")
	}
	return nil
}

// VoiceService enforces voice naming, ElevenLabs ID validation, and dependency
// checks before persistence.
type VoiceService struct {
	repo *repository.VoiceRepository
}

// NewVoiceService returns a voice service backed by repo.
func NewVoiceService(repo *repository.VoiceRepository) *VoiceService {
	return &VoiceService{
		repo: repo,
	}
}

// UpdateVoiceRequest carries PATCH-style voice fields.
// ClearElevenLabsVoiceID distinguishes JSON null from an omitted field.
type UpdateVoiceRequest struct {
	Name                   *string `json:"name"`
	ElevenLabsVoiceID      *string `json:"elevenlabs_voice_id"`
	ClearElevenLabsVoiceID bool    `json:"clear_elevenlabs_voice_id"`
}

// Create validates the optional ElevenLabs voice ID before persisting a voice.
func (s *VoiceService) Create(ctx context.Context, name string, elevenLabsVoiceID *string) (*models.Voice, error) {
	if err := validateElevenLabsVoiceID(elevenLabsVoiceID); err != nil {
		return nil, err
	}

	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if taken {
		return nil, apperrors.Duplicate("Voice", "name", name)
	}

	voice, err := s.repo.Create(ctx, name, elevenLabsVoiceID)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpCreate, err)
	}

	return voice, nil
}

// Update applies voice changes after validating any new ElevenLabs ID and
// ensuring a renamed voice remains unique.
func (s *VoiceService) Update(ctx context.Context, id int64, req *UpdateVoiceRequest) (*models.Voice, error) {
	if err := validateElevenLabsVoiceID(req.ElevenLabsVoiceID); err != nil {
		return nil, err
	}

	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return nil, apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
		}
		if taken {
			return nil, apperrors.Duplicate("Voice", "name", *req.Name)
		}
	}

	updates := &repository.VoiceUpdate{
		Name:                   req.Name,
		ElevenLabsVoiceID:      req.ElevenLabsVoiceID,
		ClearElevenLabsVoiceID: req.ClearElevenLabsVoiceID,
	}

	if err := s.repo.Update(ctx, id, updates); err != nil {
		return nil, apperrors.TranslateRepoError("Voice", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// Delete removes a voice only when no stories or station-voice relationships
// depend on it.
func (s *VoiceService) Delete(ctx context.Context, id int64) error {
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if !exists {
		return apperrors.NotFoundWithID("Voice", id)
	}

	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Voice", apperrors.OpQuery, err)
	}
	if hasDeps {
		return apperrors.Dependency("Voice", "stories or station_voices")
	}

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
