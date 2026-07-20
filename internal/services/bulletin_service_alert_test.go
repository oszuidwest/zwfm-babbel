package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/audio"
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

func TestBulletinServiceAlertsWhenJingleIsMissing(t *testing.T) {
	alerts := &capturingAlerter{}
	service := &BulletinService{
		config: &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}},
		alerts: alerts,
	}
	voiceID := int64(9)

	service.reportJingleAvailability(t.Context(), 3, audio.JingleContext{VoiceID: &voiceID})
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestBulletinServiceAlertsWhenJingleVoiceIsAbsent(t *testing.T) {
	alerts := &capturingAlerter{}
	service := &BulletinService{alerts: alerts}

	service.reportJingleAvailability(t.Context(), 3, audio.JingleContext{})
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestBulletinServiceResolvesMissingJingleAcrossVoiceChanges(t *testing.T) {
	processedPath := t.TempDir()
	alerts := &capturingAlerter{}
	service := &BulletinService{
		config: &config.Config{Audio: config.AudioConfig{ProcessedPath: processedPath}},
		alerts: alerts,
	}
	missingVoiceID, availableVoiceID := int64(9), int64(10)

	service.reportJingleAvailability(t.Context(), 3, audio.JingleContext{VoiceID: &missingVoiceID})
	availablePath := filepath.Join(processedPath, "station_3_voice_10_jingle.wav")
	if err := os.WriteFile(availablePath, []byte("jingle"), 0o600); err != nil {
		t.Fatalf("write jingle: %v", err)
	}
	service.reportJingleAvailability(t.Context(), 3, audio.JingleContext{VoiceID: &availableVoiceID})

	if len(alerts.resolved) != 1 || alerts.resolved[0] != "bulletin:missing-jingle:station:3" {
		t.Fatalf("resolved = %v, want stable station jingle key", alerts.resolved)
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
