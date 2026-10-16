//go:build integration

package services

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

// probingStoryRepository probes between the restore and update.
type probingStoryRepository struct {
	*repository.StoryRepository
	probe func()
}

func (r probingStoryRepository) Restore(ctx context.Context, id int64, actorUserID *int64) error {
	err := r.StoryRepository.Restore(ctx, id, actorUserID)
	r.probe()
	return err
}

func TestStoryService_RestoreAppliesUpdateAtomically(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station, story := createSelectableDeletedStory(t, db)
	today := time.Now()
	later := today.AddDate(0, 0, 10)
	start := later.Format(time.DateOnly)

	// Bulletin selection runs outside the restore's transaction, on another connection.
	var midRestore []repository.BulletinStoryData
	probed := false
	reader := repository.NewStoryRepository(db)
	service := &StoryService{
		storyRepo: probingStoryRepository{
			StoryRepository: reader,
			probe: func() {
				probed = true
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

	actor := int64(307)
	restored, err := service.Restore(t.Context(), story.ID, &UpdateStoryRequest{ActorUserID: &actor, StartDate: &start, EndDate: &start})
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if restored.DeletedAt.Valid || time.Time(restored.StartDate).Format(time.DateOnly) != start {
		t.Fatalf("Restore() returned stale state: %+v", restored)
	}
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ? AND action IN ?", models.AuditEntityStory, story.ID,
		[]models.AuditAction{models.AuditActionRestore, models.AuditActionUpdate}).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Action != models.AuditActionRestore || events[1].Action != models.AuditActionUpdate {
		t.Fatalf("restore audit events = %+v", events)
	}
	for _, event := range events {
		if event.UserID == nil || *event.UserID != actor {
			t.Fatalf("restore audit actor = %v, want %d", event.UserID, actor)
		}
	}
	if !probed {
		t.Fatal("probe did not run during the restore")
	}
	if containsStory(midRestore, story.ID) {
		t.Fatal("bulletin selection saw the restored story with its old window before the update committed")
	}
	selected, err := reader.GetStoriesForBulletin(t.Context(), station.ID, later, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !containsStory(selected, story.ID) {
		t.Fatal("restored story not selectable on its new start date")
	}
}

func TestStoryService_RestoreRollsBackWhenUpdateFails(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	_, story := createSelectableDeletedStory(t, db)
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
	var restoreEvents int64
	if err := db.Model(&models.AuditEvent{}).
		Where("entity_type = ? AND entity_id = ? AND action = ?", models.AuditEntityStory, story.ID, models.AuditActionRestore).
		Count(&restoreEvents).Error; err != nil {
		t.Fatal(err)
	}
	if restoreEvents != 0 {
		t.Fatal("a failed update left a restore audit event")
	}
}

// createSelectableDeletedStory creates a deleted story eligible for today's bulletin.
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
		for _, err := range []error{
			db.Unscoped().Where("voice_id = ?", voice.ID).Delete(&models.Story{}).Error,
			db.Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, story.ID).Delete(&models.AuditEvent{}).Error,
			db.Where("voice_id = ?", voice.ID).Delete(&models.StationVoice{}).Error,
			db.Delete(&voice).Error,
		} {
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	if err := repo.UpdateAudio(t.Context(), story.ID, repository.StoryAudioUpdate{
		Action: models.AuditActionAudio, AudioFile: "restore.wav", DurationSeconds: 10,
		Publish: func() error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if selected, err := repo.GetStoriesForBulletin(t.Context(), station.ID, today, 5); err != nil || !containsStory(selected, story.ID) {
		t.Fatalf("precondition: live story not selectable today (err %v)", err)
	}
	if err := repo.SoftDelete(t.Context(), story.ID, nil); err != nil {
		t.Fatal(err)
	}
	return station, *story
}

func containsStory(stories []repository.BulletinStoryData, id int64) bool {
	return slices.ContainsFunc(stories, func(s repository.BulletinStoryData) bool { return s.ID == id })
}
