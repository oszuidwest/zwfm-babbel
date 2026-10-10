//go:build integration

package repository

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

func TestStoryRepositoryIntegration_UpdateVoiceGuard(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	voiceA, voiceB := createIntegrationVoice(t, db), createIntegrationVoice(t, db)

	withAudio := createIntegrationStory(t, db, &voiceA, "story_audio.wav")
	if err := repo.Update(t.Context(), withAudio, &StoryUpdate{VoiceID: &voiceB}); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("Update() voice change with audio error = %v, want ErrStateConflict", err)
	}
	title := "Updated"
	if err := repo.Update(t.Context(), withAudio, &StoryUpdate{VoiceID: &voiceA, Title: &title}); err != nil {
		t.Fatalf("Update() with current voice error = %v", err)
	}
	if err := repo.Update(t.Context(), withAudio, &StoryUpdate{VoiceID: &voiceA, Title: &title}); err != nil {
		t.Fatalf("Update() repeated guarded write error = %v", err)
	}
	if err := repo.SoftDelete(t.Context(), withAudio); err != nil {
		t.Fatal(err)
	}
	if err := repo.Update(t.Context(), withAudio, &StoryUpdate{VoiceID: &voiceB}); err == nil {
		t.Fatal("Update() deleted story succeeded")
	} else if _, ok := errors.AsType[*StoryDeletedError](err); !ok {
		t.Fatalf("Update() deleted story error = %v, want StoryDeletedError", err)
	}

	withoutAudio := createIntegrationStory(t, db, &voiceA, "")
	if err := repo.Update(t.Context(), withoutAudio, &StoryUpdate{VoiceID: &voiceB}); err != nil {
		t.Fatalf("Update() voice change without audio error = %v", err)
	}
	assertIntegrationStoryVoice(t, repo, withoutAudio, voiceB, "")

	if err := repo.Update(t.Context(), 1<<40, &StoryUpdate{VoiceID: &voiceB}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update() missing story error = %v, want ErrNotFound", err)
	}
}

func TestStoryRepositoryIntegration_UpdateAudioGuard(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	voiceA, voiceB := createIntegrationVoice(t, db), createIntegrationVoice(t, db)

	noVoice := createIntegrationStory(t, db, nil, "")
	err := repo.UpdateAudio(t.Context(), noVoice, StoryAudioUpdate{
		AudioFile: "story_new.wav", DurationSeconds: 3, VoiceID: voiceB,
	})
	if err != nil {
		t.Fatalf("UpdateAudio() for story without voice error = %v", err)
	}
	assertIntegrationStoryVoice(t, repo, noVoice, voiceB, "story_new.wav")

	story := createIntegrationStory(t, db, &voiceA, "story_old.wav")
	stale := StoryAudioUpdate{
		AudioFile: "story_next.wav", DurationSeconds: 3, VoiceID: voiceA,
		ExpectedVoiceID: &voiceB, ExpectedAudioFile: "story_old.wav",
	}
	if err := repo.UpdateAudio(t.Context(), story, stale); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("UpdateAudio() with stale voice error = %v, want ErrStateConflict", err)
	}
	stale.ExpectedVoiceID, stale.ExpectedAudioFile = &voiceA, "story_other.wav"
	if err := repo.UpdateAudio(t.Context(), story, stale); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("UpdateAudio() with stale audio error = %v, want ErrStateConflict", err)
	}

	err = repo.UpdateAudio(t.Context(), story, StoryAudioUpdate{
		AudioFile: "story_next.wav", DurationSeconds: 3, VoiceID: voiceB,
		ExpectedVoiceID: &voiceA, ExpectedAudioFile: "story_old.wav",
	})
	if err != nil {
		t.Fatalf("UpdateAudio() replacing voice and audio error = %v", err)
	}
	assertIntegrationStoryVoice(t, repo, story, voiceB, "story_next.wav")
}

func createIntegrationVoice(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	voice := &models.Voice{Name: fmt.Sprintf("integration-voice-%d", time.Now().UnixNano())}
	if err := db.Create(voice).Error; err != nil {
		t.Fatalf("create voice: %v", err)
	}
	t.Cleanup(func() { db.Delete(&models.Voice{}, voice.ID) })
	return voice.ID
}

func createIntegrationStory(t *testing.T, db *gorm.DB, voiceID *int64, audioFile string) int64 {
	t.Helper()
	story := &models.Story{
		Title:     "Integration story",
		Text:      "Integration story text",
		VoiceID:   voiceID,
		AudioFile: audioFile,
		StartDate: models.Date(time.Now()),
		EndDate:   models.Date(time.Now()),
		Weekdays:  models.WeekdaysAll,
	}
	if err := db.Create(story).Error; err != nil {
		t.Fatalf("create story: %v", err)
	}
	// Registered after the voice cleanup, so it runs first.
	t.Cleanup(func() { db.Unscoped().Delete(&models.Story{}, story.ID) })
	return story.ID
}

func assertIntegrationStoryVoice(t *testing.T, repo *StoryRepository, id, wantVoice int64, wantAudio string) {
	t.Helper()
	story, err := repo.GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if story.VoiceID == nil || *story.VoiceID != wantVoice {
		t.Fatalf("voice_id = %v, want %d", story.VoiceID, wantVoice)
	}
	if story.AudioFile != wantAudio {
		t.Fatalf("audio_file = %q, want %q", story.AudioFile, wantAudio)
	}
}

func TestStoryRepositoryIntegration_AudioWriteAfterDeletion(t *testing.T) {
	db := openIntegrationDB(t).Begin()
	if db.Error != nil {
		t.Fatal(db.Error)
	}
	defer db.Rollback()
	repo := NewStoryRepository(db)
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.Local)
	voice := createIntegrationVoice(t, db)
	story, err := repo.Create(t.Context(), &StoryCreateData{
		Title: "Audio write", Text: "News", VoiceID: &voice, Status: "active", StartDate: date, EndDate: date, Weekdays: models.WeekdaysAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateAudio(t.Context(), story.ID, StoryAudioUpdate{
		AudioFile: "original.wav", DurationSeconds: 12, VoiceID: voice, ExpectedVoiceID: &voice,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.SoftDelete(t.Context(), story.ID); err != nil {
		t.Fatal(err)
	}
	replacement := StoryAudioUpdate{
		AudioFile: "replacement.wav", DurationSeconds: 20, VoiceID: voice,
		ExpectedVoiceID: &voice, ExpectedAudioFile: "original.wav",
	}
	err = repo.UpdateAudio(t.Context(), story.ID, replacement)
	deleted, ok := errors.AsType[*StoryDeletedError](err)
	if !ok || deleted.ID != story.ID || deleted.DeletedAt.IsZero() {
		t.Fatalf("UpdateAudio after deletion = %v, want deletion timestamp", err)
	}
	var saved models.Story
	if err := db.Unscoped().First(&saved, story.ID).Error; err != nil {
		t.Fatal(err)
	}
	if saved.AudioFile != "original.wav" || saved.DurationSeconds == nil || *saved.DurationSeconds != 12 {
		t.Fatalf("deleted story audio changed: %+v", saved)
	}
	if err := repo.UpdateAudio(t.Context(), math.MaxInt64, replacement); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateAudio missing = %v, want ErrNotFound", err)
	}
}

func TestStoryRepositoryIntegration_CalendarDatesAndBulletinSelection(t *testing.T) {
	db := openIntegrationDB(t).Begin()
	if db.Error != nil {
		t.Fatal(db.Error)
	}
	defer db.Rollback()
	station := models.Station{Name: fmt.Sprintf("date-station-%d", time.Now().UnixNano())}
	voice := models.Voice{Name: fmt.Sprintf("date-voice-%d", time.Now().UnixNano())}
	if err := db.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.StationVoice{StationID: station.ID, VoiceID: voice.ID, MixPoint: 1.5}).Error; err != nil {
		t.Fatal(err)
	}
	repo := NewStoryRepository(db)
	date := time.Date(2026, 9, 26, 0, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	story, err := repo.Create(t.Context(), &StoryCreateData{
		Title: "Calendar day", Text: "News", VoiceID: &voice.ID, Status: "active",
		StartDate: date, EndDate: date, Weekdays: models.WeekdaySaturday,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateAudio(t.Context(), story.ID, StoryAudioUpdate{
		AudioFile: "calendar.wav", DurationSeconds: 10, VoiceID: voice.ID, ExpectedVoiceID: &voice.ID,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		date time.Time
		want int
	}{
		{name: "before range", date: date.AddDate(0, 0, -7), want: 0},
		{name: "inclusive range at midnight", date: date, want: 1},
		{name: "inclusive range late in day", date: date.Add(23 * time.Hour), want: 1},
		{name: "after range", date: date.AddDate(0, 0, 7), want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			stories, err := repo.GetStoriesForBulletin(t.Context(), station.ID, tt.date, 5)
			if err != nil {
				t.Fatal(err)
			}
			if len(stories) != tt.want {
				t.Fatalf("selected %d stories, want %d", len(stories), tt.want)
			}
			if tt.want == 1 {
				assertStoryDateJSON(t, stories[0], "2026-09-26")
				if stories[0].MixPoint != 1.5 || stories[0].ID != story.ID {
					t.Fatalf("unexpected embedded story: %+v", stories[0])
				}
			}
		})
	}
}

func assertStoryDateJSON(t *testing.T, story any, want string) {
	t.Helper()
	data, err := json.Marshal(story)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["start_date"] != want || fields["end_date"] != want {
		t.Fatalf("story dates = %v/%v, want %s", fields["start_date"], fields["end_date"], want)
	}
}
