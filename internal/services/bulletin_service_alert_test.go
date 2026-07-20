package services

import (
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func TestBulletinServiceAlertsForMissingStoryAudio(t *testing.T) {
	alerts := &capturingAlerter{}
	service := &BulletinService{
		config: &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}},
		alerts: alerts,
	}

	stories := []repository.BulletinStoryData{{Story: models.Story{ID: 42}}}
	got := service.filterStoriesWithMissingAudio(t.Context(), stories, 7)
	if len(got) != 0 {
		t.Fatalf("kept stories = %d, want 0", len(got))
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
		{Story: models.Story{ID: 1}},
		{Story: models.Story{ID: 2, VoiceID: &voiceOne}},
		{Story: models.Story{ID: 3, VoiceID: &voiceTwo}},
	}

	service.reportVoiceConsistency(t.Context(), 7, stories)
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:multiple-voices:station:7" {
		t.Fatalf("events = %+v", alerts.events)
	}
}
