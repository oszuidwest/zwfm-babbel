package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestGenerateTTS_CallerCancellationDoesNotAlert(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		err        error
		cancel     bool
		wantAlerts int
	}{
		{name: "caller disconnect", err: fmt.Errorf("request: %w", context.Canceled), cancel: true},
		{name: "upstream cancellation", err: context.Canceled, wantAlerts: 1},
		{name: "client timeout", err: &tts.TransportError{Err: context.DeadlineExceeded}, wantAlerts: 1},
		{name: "transport failure", err: &tts.TransportError{Err: errors.New("connection reset")}, wantAlerts: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			generator := &fakeSpeechGenerator{err: tt.err}
			if tt.cancel {
				generator.beforeReturn = cancel
			}
			service := newGenerateTTSTestService(storyForTTSTest("news"), &models.TTSSettings{}, nil, generator)
			alerts := &capturingAlerter{}
			service.alerts = alerts
			if err := service.GenerateTTS(ctx, 99, false, nil); !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want original cause %v", err, tt.err)
			}
			if len(alerts.events) != tt.wantAlerts || len(alerts.resolved) != 0 {
				t.Fatalf("alerts = %+v, resolved = %v; want %d occurrences and no recovery", alerts.events, alerts.resolved, tt.wantAlerts)
			}
			for _, event := range alerts.events {
				if event.Key != "tts:upstream" || !event.RequiresThreshold {
					t.Fatalf("event = %+v, want thresholded upstream alert", event)
				}
			}
		})
	}
}

func TestGenerateTTS_UndecodableOutputIsUpstreamFailure(t *testing.T) {
	t.Parallel()
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	story := storyForTTSTest("news")
	service := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, &fakeSpeechGenerator{data: []byte("not audio")})
	service.config = &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir(), FFmpegPath: ffmpeg, FFprobePath: ffprobe}}
	service.audioSvc = audio.NewService(service.config, nil)
	alerts := &capturingAlerter{}
	service.alerts = alerts
	path := utils.StoryPath(service.config, story.ID)
	existing := []byte("previous audio")
	if err := os.WriteFile(path, existing, 0600); err != nil {
		t.Fatal(err)
	}
	err = service.GenerateTTS(t.Context(), story.ID, true, nil)
	assertUpstreamError(t, err, http.StatusBadGateway)
	if !errors.Is(err, audio.ErrUndecodable) {
		t.Fatalf("error = %v, want ffprobe rejection as cause", err)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "tts:upstream" || !alerts.events[0].RequiresThreshold || len(alerts.resolved) != 0 {
		t.Fatalf("alerts = %+v, resolved = %v; want one thresholded upstream alert", alerts.events, alerts.resolved)
	}
	// #nosec G304 - canonical fixture in t.TempDir.
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, existing) {
		t.Fatalf("existing audio = %q, %v; want unchanged", data, err)
	}
}
