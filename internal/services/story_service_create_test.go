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
	service := &StoryService{storyRepo: &raceStoryRepository{storyRepository: &fakeStoryRepository{err: databaseDown}}}

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

// Create always loses to a concurrent create with the same idempotency key.
func (f *fakeStoryRepository) Create(context.Context, *repository.StoryCreateData) (*models.Story, error) {
	return nil, repository.ErrDuplicateKey
}

func (f *fakeStoryRepository) GetIDByIdempotencyKey(context.Context, string) (int64, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	return f.story.ID, nil
}

func idempotentCreate(title, key string) *CreateStoryRequest {
	today := time.Now().Format(time.DateOnly)
	return &CreateStoryRequest{
		Title: title, Text: "News", Status: string(models.StoryStatusDraft),
		StartDate: today, EndDate: today, Weekdays: models.WeekdaysAll, IdempotencyKey: &key,
	}
}
