package services

import (
	"os"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestBulletinServiceAlertsForMissingStoryAudio(t *testing.T) {
	alerts := &capturingAlerter{}
	cfg := &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}}
	service := &BulletinService{config: cfg, alerts: alerts}
	present := repository.BulletinStoryData{ID: 41, AudioFile: "story_41_voice_1_abc.wav"}
	if err := os.WriteFile(utils.StoryPath(cfg, present.AudioFile), []byte("audio"), 0600); err != nil {
		t.Fatal(err)
	}

	stories := []repository.BulletinStoryData{present, {ID: 42, AudioFile: "story_42_voice_1_abc.wav"}}
	got := service.filterStoriesWithMissingAudio(t.Context(), stories, 7)
	if len(got) != 1 || got[0].ID != present.ID {
		t.Fatalf("kept stories = %+v, want only story %d", got, present.ID)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-story-audio:station:7:story:42" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestBulletinServiceAlertsForMultipleVoicesRegardlessOfFirstStory(t *testing.T) {
	alerts := &capturingAlerter{}
	service := &BulletinService{alerts: alerts}
	voiceOne, voiceTwo := int64(11), int64(22)
	stories := []repository.BulletinStoryData{
		{ID: 1},
		{ID: 2, VoiceID: &voiceOne},
		{ID: 3, VoiceID: &voiceTwo},
	}

	service.reportVoiceConsistency(t.Context(), 7, stories)
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:multiple-voices:station:7" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestPrepareStoriesForPlaybackCapturesJingleBeforeShuffle(t *testing.T) {
	voiceID := int64(11)
	stories := []repository.BulletinStoryData{
		{ID: 1, VoiceID: &voiceID, MixPoint: 5},
		{ID: 2, MixPoint: 0.5},
	}

	jingle := prepareStoriesForPlayback(stories, func(n int, swap func(int, int)) {
		if n != 2 {
			t.Fatalf("shuffle size = %d, want 2", n)
		}
		swap(0, 1)
	})

	if jingle.VoiceID != &voiceID || jingle.MixPoint != 5 {
		t.Fatalf("jingle = %+v, want first story voice and mix point", jingle)
	}
	if stories[0].ID != 2 || stories[1].ID != 1 {
		t.Fatalf("stories = %+v, want injected shuffle to change playback order", stories)
	}
}
