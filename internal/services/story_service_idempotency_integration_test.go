//go:build integration

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func TestStoryService_CreateWithIdempotencyKeyReturnsTheFirstStory(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newIdempotencyTestService(db)
	key := newIdempotencyKey(t, db)

	first, err := service.Create(t.Context(), idempotentCreate("First", key))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	// A repeat with another body still answers with the first story, without storing the body.
	again, err := service.Create(t.Context(), idempotentCreate("Second", key))
	if err != nil || again != first {
		t.Fatalf("repeated Create() = %d, %v; want %d", again, err, first)
	}
	assertOneStoryWithKey(t, db, key)
	var stored models.Story
	if err := db.First(&stored, first).Error; err != nil || stored.Title != "First" {
		t.Fatalf("stored story = %q, %v; want the first body", stored.Title, err)
	}

	// The key still belongs to the story after it was deleted.
	if err := repository.NewStoryRepository(db).SoftDelete(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	afterDelete, err := service.Create(t.Context(), idempotentCreate("Third", key))
	if err != nil || afterDelete != first {
		t.Fatalf("Create() after deletion = %d, %v; want %d", afterDelete, err, first)
	}
	assertOneStoryWithKey(t, db, key)
}

func TestStoryService_ConcurrentCreatesWithOneKeyMakeOneStory(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newIdempotencyTestService(db)
	key := newIdempotencyKey(t, db)

	const creates = 8
	ids := make([]int64, creates)
	errs := make([]error, creates)
	var wg sync.WaitGroup
	for i := range creates {
		wg.Go(func() {
			ids[i], errs[i] = service.Create(t.Context(), idempotentCreate(fmt.Sprintf("Concurrent %d", i), key))
		})
	}
	wg.Wait()

	for i := range creates {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("create %d = %d, %v; want %d", i, ids[i], errs[i], ids[0])
		}
	}
	assertOneStoryWithKey(t, db, key)
}

func TestStoryService_CreateComparesIdempotencyKeysExactly(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newIdempotencyTestService(db)
	key := newIdempotencyKey(t, db)
	others := []string{strings.ToUpper(key), key + " "}
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key IN ?", others).Delete(&models.Story{}) })

	first, err := service.Create(t.Context(), idempotentCreate("Original", key))
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range others {
		id, err := service.Create(t.Context(), idempotentCreate("Other", other))
		if err != nil || id == first {
			t.Fatalf("Create() with key %q = %d, %v; want a new story", other, id, err)
		}
	}
}

// raceStoryRepository hides the first lookup of a key, as when a concurrent create commits right
// after it, and can fail the lookup after that.
type raceStoryRepository struct {
	*repository.StoryRepository
	lookups   int
	secondErr error
}

func (r *raceStoryRepository) GetIDByIdempotencyKey(ctx context.Context, key string) (int64, error) {
	r.lookups++
	if r.lookups == 1 {
		return 0, repository.ErrNotFound
	}
	if r.secondErr != nil {
		return 0, r.secondErr
	}
	return r.StoryRepository.GetIDByIdempotencyKey(ctx, key)
}

func TestStoryService_CreateRecoversFromAConcurrentCreateWithTheSameKey(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	key := newIdempotencyKey(t, db)
	winner, err := newIdempotencyTestService(db).Create(t.Context(), idempotentCreate("Winner", key))
	if err != nil {
		t.Fatal(err)
	}

	repo := &raceStoryRepository{StoryRepository: repository.NewStoryRepository(db)}
	service := newIdempotencyTestService(db)
	service.storyRepo = repo
	id, err := service.Create(t.Context(), idempotentCreate("Loser", key))
	if err != nil || id != winner || repo.lookups != 2 {
		t.Fatalf("Create() = %d, %v after %d lookups; want %d after the duplicate key", id, err, repo.lookups, winner)
	}
	assertOneStoryWithKey(t, db, key)

	// A failed lookup after the duplicate key is reported as such, not as a conflict.
	databaseDown := errors.New("database down")
	service.storyRepo = &raceStoryRepository{StoryRepository: repo.StoryRepository, secondErr: databaseDown}
	_, err = service.Create(t.Context(), idempotentCreate("Loser", key))
	if _, database := errors.AsType[*apperrors.DatabaseError](err); !database || !errors.Is(err, databaseDown) {
		t.Fatalf("Create() with a failing lookup error = %v, want the lookup's database error", err)
	}
}

func newIdempotencyTestService(db *gorm.DB) *StoryService {
	return &StoryService{
		storyRepo: repository.NewStoryRepository(db),
		voiceRepo: repository.NewVoiceRepository(db),
	}
}

// newIdempotencyKey returns a key unique to this test run and deletes the stories made with it
// when the test ends.
func newIdempotencyKey(t *testing.T, db *gorm.DB) string {
	t.Helper()
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key = ?", key).Delete(&models.Story{}) })
	return key
}

func idempotentCreate(title, key string) *CreateStoryRequest {
	today := time.Now().Format(time.DateOnly)
	return &CreateStoryRequest{
		Title: title, Text: "News", Status: string(models.StoryStatusDraft),
		StartDate: today, EndDate: today, Weekdays: models.WeekdaysAll, IdempotencyKey: &key,
	}
}

func assertOneStoryWithKey(t *testing.T, db *gorm.DB, key string) {
	t.Helper()
	var count int64
	if err := db.Unscoped().Model(&models.Story{}).Where("idempotency_key = ?", key).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d stories with key %q, want 1", count, key)
	}
}
