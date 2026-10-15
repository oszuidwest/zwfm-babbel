//go:build integration

package services

import (
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
	t.Cleanup(func() { deleteStoriesWithKeys(t, db, others...) })

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

func TestStoryService_CreateRecoversFromAConcurrentCreateWithTheSameKey(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	key := newIdempotencyKey(t, db)
	winner, err := newIdempotencyTestService(db).Create(t.Context(), idempotentCreate("Winner", key))
	if err != nil {
		t.Fatal(err)
	}

	service := &StoryService{storyRepo: &raceStoryRepository{storyRepository: repository.NewStoryRepository(db)}}
	id, err := service.Create(t.Context(), idempotentCreate("Loser", key))
	if err != nil || id != winner {
		t.Fatalf("Create() = %d, %v; want %d after the duplicate key", id, err, winner)
	}
	assertOneStoryWithKey(t, db, key)
}

func newIdempotencyTestService(db *gorm.DB) *StoryService {
	return &StoryService{storyRepo: repository.NewStoryRepository(db)}
}

// newIdempotencyKey returns a key unique to this test run and deletes the stories made with it
// when the test ends.
func newIdempotencyKey(t *testing.T, db *gorm.DB) string {
	t.Helper()
	key := fmt.Sprintf("%s-%d", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() { deleteStoriesWithKeys(t, db, key) })
	return key
}

func deleteStoriesWithKeys(t *testing.T, db *gorm.DB, keys ...string) {
	t.Helper()
	if err := db.Unscoped().Where("idempotency_key IN ?", keys).Delete(&models.Story{}).Error; err != nil {
		t.Errorf("delete stories with keys %q: %v", keys, err)
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
