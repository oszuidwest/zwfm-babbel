package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestAudioConversionDeadlinePreservesPublishedFiles(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell executable")
	}
	for _, kind := range []string{"story upload", "TTS", "jingle"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			service := newPublishAudioTestService(t)
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
			tool := filepath.Join(t.TempDir(), "hung-ffmpeg")
			if err := os.WriteFile(tool, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil { //nolint:gosec // Test executable.
				t.Fatal(err)
			}
			service.config.Audio.FFmpegPath = tool
			story := storyForTTSTest("news")
			path := utils.StoryPath(service.config, story.ID)
			stationVoice := &models.StationVoice{ID: 1, StationID: 2, VoiceID: 3}
			if kind == "jingle" {
				path = utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID)
			}
			existing := []byte("published audio must remain intact")
			if err := os.WriteFile(path, existing, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			var err error
			switch kind {
			case "story upload":
				err = service.ProcessAudio(ctx, story.ID, input, nil)
			case "TTS":
				data, readErr := os.ReadFile(input)
				if readErr != nil {
					t.Fatal(readErr)
				}
				tts := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, &fakeSpeechGenerator{data: data})
				tts.config, tts.audioSvc = service.config, service.audioSvc
				err = tts.GenerateTTS(ctx, story.ID, true, nil)
			case "jingle":
				jingle := &StationVoiceService{config: service.config, audioSvc: service.audioSvc}
				err = jingle.ProcessJingle(ctx, stationVoice, input)
			}
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, audio.ErrUndecodable) {
				t.Fatalf("error = %v, want preserved deadline", err)
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, existing) {
				t.Fatalf("published audio = %q, %v", got, err)
			}
			for _, dir := range []string{service.config.Audio.TempPath, service.config.Audio.ProcessedPath} {
				entries, err := os.ReadDir(dir)
				if err != nil || (dir == service.config.Audio.TempPath && len(entries) != 0) || (dir == service.config.Audio.ProcessedPath && len(entries) != 1) {
					t.Fatalf("conversion leftovers in %s: %v, %v", dir, entries, err)
				}
			}
		})
	}
}
