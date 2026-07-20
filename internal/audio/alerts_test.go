package audio

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
)

type alertRecorder struct {
	events   []notify.Event
	resolved []string
}

func (a *alertRecorder) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *alertRecorder) Resolve(_ context.Context, key, _, _ string) {
	a.resolved = append(a.resolved, key)
}

func TestAddJingleMixWithoutJingleMixesMessagesOnly(t *testing.T) {
	alerts := &alertRecorder{}
	service := NewService(&config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}}, alerts)
	voiceID := int64(9)

	_, filters := service.addJingleMix(
		t.Context(), nil, nil, &models.Station{ID: 3}, JingleContext{VoiceID: &voiceID}, 1,
	)
	if len(filters) != 1 || filters[0] != "[messages]anull[mixed]" {
		t.Fatalf("filters = %v", filters)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestAddJingleMixAlertsWithoutVoice(t *testing.T) {
	alerts := &alertRecorder{}
	service := NewService(&config.Config{}, alerts)

	service.addJingleMix(t.Context(), nil, nil, &models.Station{ID: 3}, JingleContext{}, 1)
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3" {
		t.Fatalf("events = %+v", alerts.events)
	}
}

func TestAddJingleMixResolvesAcrossVoiceChanges(t *testing.T) {
	processedPath := t.TempDir()
	alerts := &alertRecorder{}
	service := NewService(&config.Config{Audio: config.AudioConfig{ProcessedPath: processedPath}}, alerts)
	missingVoiceID, availableVoiceID := int64(9), int64(10)
	station := &models.Station{ID: 3}

	service.addJingleMix(t.Context(), nil, nil, station, JingleContext{VoiceID: &missingVoiceID}, 1)
	availablePath := filepath.Join(processedPath, "station_3_voice_10_jingle.wav")
	if err := os.WriteFile(availablePath, []byte("jingle"), 0o600); err != nil {
		t.Fatalf("write jingle: %v", err)
	}
	service.addJingleMix(t.Context(), nil, nil, station, JingleContext{VoiceID: &availableVoiceID}, 1)

	if len(alerts.resolved) != 1 || alerts.resolved[0] != "bulletin:missing-jingle:station:3" {
		t.Fatalf("resolved = %v, want stable station jingle key", alerts.resolved)
	}
}

func TestAddJingleMixRejectsNonRegularJingle(t *testing.T) {
	processedPath := t.TempDir()
	alerts := &alertRecorder{}
	service := NewService(&config.Config{Audio: config.AudioConfig{ProcessedPath: processedPath}}, alerts)
	voiceID := int64(10)
	jinglePath := filepath.Join(processedPath, "station_3_voice_10_jingle.wav")
	if err := os.Mkdir(jinglePath, 0o700); err != nil {
		t.Fatalf("create jingle directory: %v", err)
	}

	args, filters := service.addJingleMix(
		t.Context(), nil, nil, &models.Station{ID: 3}, JingleContext{VoiceID: &voiceID}, 1,
	)

	if len(args) != 0 {
		t.Fatalf("args = %v, want no jingle input", args)
	}
	if len(filters) != 1 || filters[0] != "[messages]anull[mixed]" {
		t.Fatalf("filters = %v", filters)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3" {
		t.Fatalf("events = %+v", alerts.events)
	}
	if len(alerts.resolved) != 0 {
		t.Fatalf("resolved = %v, want no recovery", alerts.resolved)
	}
}
