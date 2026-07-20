package audio

import (
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestAddJingleMixWithoutJingleMixesMessagesOnly(t *testing.T) {
	service := NewService(&config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir()}}, nil)
	voiceID := int64(9)

	_, filters := service.addJingleMix(
		nil, nil, &models.Station{ID: 3}, JingleContext{VoiceID: &voiceID}, 1,
	)
	if len(filters) != 1 || filters[0] != "[messages]anull[mixed]" {
		t.Fatalf("filters = %v", filters)
	}
}
