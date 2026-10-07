//go:build integration

package repository

import (
	"errors"
	"fmt"
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
		StartDate: time.Now(),
		EndDate:   time.Now(),
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
