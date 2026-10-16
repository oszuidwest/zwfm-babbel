package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestStoryService_CreateReportsAFailedLookupAfterADuplicateKey(t *testing.T) {
	t.Parallel()
	databaseDown := errors.New("database down")
	service := &StoryService{storyRepo: &raceStoryRepository{storyRepository: &duplicateKeyRepository{lookupErr: databaseDown}}}

	_, err := service.Create(t.Context(), idempotentCreate("Loser", "key"))
	if _, database := errors.AsType[*apperrors.DatabaseError](err); !database || !errors.Is(err, databaseDown) {
		t.Fatalf("Create() error = %v, want the lookup's database error", err)
	}
}

// raceStoryRepository misses the first idempotency key lookup, as when a concurrent create with
// the same key commits right after it.
type raceStoryRepository struct {
	storyRepository
	missed bool
}

func (r *raceStoryRepository) GetIDByIdempotencyKey(ctx context.Context, key string) (int64, error) {
	if !r.missed {
		r.missed = true
		return 0, repository.ErrNotFound
	}
	return r.storyRepository.GetIDByIdempotencyKey(ctx, key)
}

// duplicateKeyRepository always loses a create to a concurrent one with the same idempotency key.
type duplicateKeyRepository struct {
	storyRepository
	lookupErr error
}

func (r *duplicateKeyRepository) Create(context.Context, *repository.StoryCreateData) (*models.Story, error) {
	return nil, repository.ErrDuplicateKey
}

func (r *duplicateKeyRepository) GetIDByIdempotencyKey(context.Context, string) (int64, error) {
	return 0, r.lookupErr
}

func idempotentCreate(title, key string) *CreateStoryRequest {
	today := time.Now().Format(time.DateOnly)
	return &CreateStoryRequest{
		Title: title, Text: "News", Status: string(models.StoryStatusDraft),
		StartDate: today, EndDate: today, Weekdays: models.WeekdaysAll, IdempotencyKey: &key,
	}
}
