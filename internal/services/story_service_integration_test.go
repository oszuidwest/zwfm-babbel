//go:build integration

package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

// probingStoryRepository runs probe right after each update, while a restore's
// transaction is still open.
type probingStoryRepository struct {
	*repository.StoryRepository
	probe func()
}

func (r probingStoryRepository) Update(ctx context.Context, id int64, u *repository.StoryUpdate) error {
	err := r.StoryRepository.Update(ctx, id, u)
	r.probe()
	return err
}

func TestStoryService_RestoreAppliesUpdateAtomically(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station, story := createSelectableDeletedStory(t, db)
	today := time.Now()
	start := today.AddDate(0, 0, 10).Format(time.DateOnly)
	weekdays := models.WeekdaysAll

	// Bulletin selection runs outside the restore's transaction, on another connection.
	var midRestore []repository.BulletinStoryData
	reader := repository.NewStoryRepository(db)
	service := &StoryService{
		storyRepo: probingStoryRepository{
			StoryRepository: repository.NewStoryRepository(db),
			probe: func() {
				var err error
				midRestore, err = reader.GetStoriesForBulletin(context.Background(), station.ID, today, 5)
				if err != nil {
					t.Errorf("GetStoriesForBulletin() during restore: %v", err)
				}
			},
		},
		voiceRepo: repository.NewVoiceRepository(db),
		txManager: repository.NewTxManager(db),
	}

	restored, err := service.Restore(t.Context(), story.ID, &UpdateStoryRequest{StartDate: &start, EndDate: &start, Weekdays: &weekdays})
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if containsStory(midRestore, story.ID) {
		t.Fatal("bulletin selection saw the restored story with its old window before the update committed")
	}
	if restored.DeletedAt.Valid || time.Time(restored.StartDate).Format(time.DateOnly) != start {
		t.Fatalf("Restore() = deleted %v, start %v; want live from %s", restored.DeletedAt.Valid, restored.StartDate, start)
	}
	for _, day := range []time.Time{today, today.AddDate(0, 0, 10)} {
		selected, err := reader.GetStoriesForBulletin(t.Context(), station.ID, day, 5)
		if err != nil {
			t.Fatal(err)
		}
		if want := day.After(today); containsStory(selected, story.ID) != want {
			t.Fatalf("story selectable on %s = %v, want %v", day.Format(time.DateOnly), !want, want)
		}
	}
}

func TestStoryService_RestoreRollsBackWhenUpdateFails(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station, story := createSelectableDeletedStory(t, db)
	service := &StoryService{
		storyRepo: repository.NewStoryRepository(db),
		voiceRepo: repository.NewVoiceRepository(db),
		txManager: repository.NewTxManager(db),
	}

	// The end date lies before the start date, so the update fails after the restore ran.
	start, end := "2030-01-02", "2030-01-01"
	_, err := service.Restore(t.Context(), story.ID, &UpdateStoryRequest{StartDate: &start, EndDate: &end})
	if invalid, ok := errors.AsType[*apperrors.ValidationError](err); !ok || invalid.Errors[0].Code != apperrors.CodeDateOrder {
		t.Fatalf("Restore() error = %v, want date_order validation error", err)
	}

	var saved models.Story
	if err := db.Unscoped().First(&saved, story.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !saved.DeletedAt.Valid {
		t.Fatal("a failed update left the story restored")
	}
	selected, err := repository.NewStoryRepository(db).GetStoriesForBulletin(t.Context(), station.ID, time.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if containsStory(selected, story.ID) {
		t.Fatal("a failed restore made the story selectable")
	}
}

// createSelectableDeletedStory creates a soft-deleted story that bulletin
// selection would pick today once restored: active, with audio, a voice on the
// station, and a window covering today on every weekday.
func createSelectableDeletedStory(t *testing.T, db *gorm.DB) (models.Station, models.Story) {
	t.Helper()
	station := createTestStation(t, db)
	voice := models.Voice{Name: t.Name()}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.StationVoice{StationID: station.ID, VoiceID: voice.ID, MixPoint: 1}).Error; err != nil {
		t.Fatal(err)
	}

	repo := repository.NewStoryRepository(db)
	today := time.Now()
	story, err := repo.Create(t.Context(), &repository.StoryCreateData{
		Title: t.Name(), Text: "News", VoiceID: &voice.ID, Status: string(models.StoryStatusActive),
		StartDate: today.AddDate(0, 0, -1), EndDate: today.AddDate(0, 0, 1), Weekdays: models.WeekdaysAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Unscoped().Where("voice_id = ?", voice.ID).Delete(&models.Story{})
		db.Where("voice_id = ?", voice.ID).Delete(&models.StationVoice{})
		db.Delete(&voice)
	})
	if err := repo.UpdateAudio(t.Context(), story.ID, "restore.wav", 10); err != nil {
		t.Fatal(err)
	}
	if selected, err := repo.GetStoriesForBulletin(t.Context(), station.ID, today, 5); err != nil || !containsStory(selected, story.ID) {
		t.Fatalf("precondition: live story not selectable today (err %v)", err)
	}
	if err := repo.SoftDelete(t.Context(), story.ID); err != nil {
		t.Fatal(err)
	}
	return station, *story
}

func containsStory(stories []repository.BulletinStoryData, id int64) bool {
	for _, s := range stories {
		if s.ID == id {
			return true
		}
	}
	return false
}
