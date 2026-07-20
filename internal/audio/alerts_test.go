package audio

import (
	"context"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
)

type capturingAlerter struct {
	events []notify.Event
}

func (a *capturingAlerter) Alert(_ context.Context, event notify.Event) {
	a.events = append(a.events, event)
}

func (a *capturingAlerter) Resolve(context.Context, string, string, string) {}

func TestServiceAlertsWhenJingleIsMissing(t *testing.T) {
	alerts := &capturingAlerter{}
	service := NewService(&config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}}, alerts)
	voiceID := int64(9)

	_, filters := service.addJingleMix(
		t.Context(), nil, nil, &models.Station{ID: 3}, JingleContext{VoiceID: &voiceID}, 1,
	)
	if len(filters) != 1 || filters[0] != "[messages]anull[mixed]" {
		t.Fatalf("filters = %v", filters)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "bulletin:missing-jingle:station:3:voice:9" {
		t.Fatalf("events = %+v", alerts.events)
	}
}
