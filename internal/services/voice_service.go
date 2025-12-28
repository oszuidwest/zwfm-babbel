// Package services provides business logic services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

// VoiceService handles voice-related business logic
type VoiceService struct {
	repo   repository.VoiceRepository
	gormDB *gorm.DB
}

// NewVoiceService creates a new voice service instance
func NewVoiceService(repo repository.VoiceRepository, gormDB *gorm.DB) *VoiceService {
	return &VoiceService{
		repo:   repo,
		gormDB: gormDB,
	}
}

// UpdateVoiceRequest contains the data needed to update an existing voice.
type UpdateVoiceRequest struct {
	Name *string `json:"name"`
}

// Create creates a new voice with the given name
func (s *VoiceService) Create(ctx context.Context, name string) (*models.Voice, error) {
	const op = "VoiceService.Create"

	// Check name uniqueness
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
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
		return nil, fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return voice, nil
}

// Update updates an existing voice's name
func (s *VoiceService) Update(ctx context.Context, id int64, req *UpdateVoiceRequest) error {
	const op = "VoiceService.Update"

	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	// Check name uniqueness if name is being updated
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
		}
		if taken {
			return fmt.Errorf("%s: %w: voice name '%s'", op, apperrors.ErrDuplicate, *req.Name)
		}
	}

	// Build type-safe update struct
	updates := &repository.VoiceUpdate{
		Name: req.Name,
	}

	// Update voice
	err = s.repo.Update(ctx, id, updates)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return nil
}

// Delete deletes a voice after checking for dependencies
func (s *VoiceService) Delete(ctx context.Context, id int64) error {
	const op = "VoiceService.Delete"

	// Check if voice exists
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if !exists {
		return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
	}

	// Check for dependencies
	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}
	if hasDeps {
		return fmt.Errorf("%s: %w: voice is used by stories or stations", op, apperrors.ErrDependencyExists)
	}

	// Delete voice
	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("%s: %w", op, apperrors.ErrNotFound)
		}
		return fmt.Errorf("%s: %w: %v", op, apperrors.ErrDatabaseError, err)
	}

	return nil
}

// GetByIDWithContext retrieves a voice by ID and writes the JSON response.
func (s *VoiceService) GetByIDWithContext(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	voice, err := s.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			utils.ProblemNotFound(c, "Voice")
			return
		}
		utils.ProblemInternalServer(c, "Failed to retrieve voice")
		return
	}

	c.JSON(200, voice)
}

// ListWithContext handles paginated list requests with query parameters.
// Encapsulates query configuration and writes JSON response directly.
func (s *VoiceService) ListWithContext(c *gin.Context) {
	config := utils.GormListConfig{
		SearchFields: []string{"name"},
		FieldMapping: map[string]string{
			"id":         "id",
			"name":       "name",
			"created_at": "created_at",
			"updated_at": "updated_at",
		},
		DefaultSort: "name ASC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.Voice](c, s.gormDB, config)
}
