package services

import (
	"context"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

// StationService enforces station invariants before delegating persistence to
// the repository layer.
type StationService struct {
	repo *repository.StationRepository
}

// NewStationService returns a station service backed by repo.
func NewStationService(repo *repository.StationRepository) *StationService {
	return &StationService{
		repo: repo,
	}
}

// UpdateStationRequest carries PATCH-style station fields.
// Nil pointers leave the corresponding field unchanged.
type UpdateStationRequest struct {
	Name               *string  `json:"name"`
	MaxStoriesPerBlock *int     `json:"max_stories_per_block"`
	PauseSeconds       *float64 `json:"pause_seconds"`
}

// Create persists a station after rejecting duplicate names.
func (s *StationService) Create(ctx context.Context, name string, maxStories int, pauseSeconds float64) (*models.Station, error) {
	taken, err := s.repo.IsNameTaken(ctx, name, nil)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}
	if taken {
		return nil, apperrors.Duplicate("Station", "name", name)
	}

	station, err := s.repo.Create(ctx, name, maxStories, pauseSeconds)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpCreate, err)
	}

	return station, nil
}

// Update applies station changes after checking that any new name is still
// unique outside the current row.
func (s *StationService) Update(ctx context.Context, id int64, req *UpdateStationRequest) (*models.Station, error) {
	if req.Name != nil {
		taken, err := s.repo.IsNameTaken(ctx, *req.Name, &id)
		if err != nil {
			return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
		}
		if taken {
			return nil, apperrors.Duplicate("Station", "name", *req.Name)
		}
	}

	updates := &repository.StationUpdate{
		Name:               req.Name,
		MaxStoriesPerBlock: req.MaxStoriesPerBlock,
		PauseSeconds:       req.PauseSeconds,
	}

	if err := s.repo.Update(ctx, id, updates); err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpUpdate, err)
	}

	return s.GetByID(ctx, id)
}

// Exists reports whether a station with the given ID exists.
func (s *StationService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return false, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}
	return exists, nil
}

// Delete removes a station only when no station-voice relationships depend on it.
func (s *StationService) Delete(ctx context.Context, id int64) error {
	exists, err := s.repo.Exists(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}
	if !exists {
		return apperrors.NotFoundWithID("Station", id)
	}

	hasDeps, err := s.repo.HasDependencies(ctx, id)
	if err != nil {
		return apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}
	if hasDeps {
		return apperrors.Dependency("Station", "station_voices")
	}

	if err := s.repo.Delete(ctx, id); err != nil {
		return apperrors.TranslateRepoError("Station", apperrors.OpDelete, err)
	}

	return nil
}

// GetByID retrieves a station by ID.
func (s *StationService) GetByID(ctx context.Context, id int64) (*models.Station, error) {
	station, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}

	return station, nil
}

// List returns a paginated list of stations.
func (s *StationService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Station], error) {
	result, err := s.repo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}

	return result, nil
}
