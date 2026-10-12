//go:build integration

package services

import (
	"fmt"
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
	assertStoriesWithKey(t, db, key, 1)
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
	assertStoriesWithKey(t, db, key, 1)
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
	assertStoriesWithKey(t, db, key, 1)
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

func assertStoriesWithKey(t *testing.T, db *gorm.DB, key string, want int64) {
	t.Helper()
	var count int64
	if err := db.Unscoped().Model(&models.Story{}).Where("idempotency_key = ?", key).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%d stories with key %q, want %d", count, key, want)
	}
}
