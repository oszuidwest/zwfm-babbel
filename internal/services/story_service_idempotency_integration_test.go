//go:build integration

package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func TestStoryService_CreateWithIdempotencyKeyReturnsTheFirstStory(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newIdempotencyTestService(db)
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key = ?", key).Delete(&models.Story{}) })

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
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key = ?", key).Delete(&models.Story{}) })

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
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	other := strings.ToUpper(key)
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key IN ?", []string{key, other}).Delete(&models.Story{}) })

	first, err := service.Create(t.Context(), idempotentCreate("Lower", key))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(t.Context(), idempotentCreate("Upper", other))
	if err != nil || second == first {
		t.Fatalf("Create() with a key differing in case = %d, %v; want a new story", second, err)
	}
}

// raceStoryRepository hides the first lookup of a key, as when a concurrent create commits right
// after it.
type raceStoryRepository struct {
	*repository.StoryRepository
	lookups int
}

func (r *raceStoryRepository) GetIDByIdempotencyKey(ctx context.Context, key string) (int64, error) {
	r.lookups++
	if r.lookups == 1 {
		return 0, repository.ErrNotFound
	}
	return r.StoryRepository.GetIDByIdempotencyKey(ctx, key)
}

func TestStoryService_CreateRecoversFromAConcurrentCreateWithTheSameKey(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { db.Unscoped().Where("idempotency_key = ?", key).Delete(&models.Story{}) })
	winner, err := newIdempotencyTestService(db).Create(t.Context(), idempotentCreate("Winner", key))
	if err != nil {
		t.Fatal(err)
	}

	repo := &raceStoryRepository{StoryRepository: repository.NewStoryRepository(db)}
	service := &StoryService{storyRepo: repo, voiceRepo: repository.NewVoiceRepository(db)}
	id, err := service.Create(t.Context(), idempotentCreate("Loser", key))
	if err != nil || id != winner || repo.lookups != 2 {
		t.Fatalf("Create() = %d, %v after %d lookups; want %d after the duplicate key", id, err, repo.lookups, winner)
	}
	assertOneStoryWithKey(t, db, key)
}

func newIdempotencyTestService(db *gorm.DB) *StoryService {
	return &StoryService{
		storyRepo: repository.NewStoryRepository(db),
		voiceRepo: repository.NewVoiceRepository(db),
	}
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
