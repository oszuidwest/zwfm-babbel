package services

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestStoryService_RejectsSilentAudioBeforePublication(t *testing.T) {
	t.Parallel()
	ffmpegPath, inputPath, silentAudio := silentStoryAudioFixture(t)
	tests := []struct {
		name     string
		tts      bool
		existing bool
	}{
		{name: "upload without existing audio"},
		{name: "upload with existing audio", existing: true},
		{name: "TTS without existing audio", tts: true},
		{name: "TTS with existing audio", tts: true, existing: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, ProcessedPath: t.TempDir(),
			}}
			story := storyForTTSTest("News bulletin")
			finalPath := utils.StoryPath(cfg, story.ID)
			existingAudio := []byte("existing audio must stay intact")
			if tt.existing {
				story.AudioFile = utils.StoryFilename(story.ID)
				if err := os.WriteFile(finalPath, existingAudio, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ttsSvc := &fakeSpeechGenerator{data: silentAudio}
			service := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, ttsSvc)
			service.config = cfg
			service.audioSvc = audio.NewService(cfg, nil)
			repo := &fakeStoryRepository{story: story}
			service.storyRepo = repo

			var err error
			if tt.tts {
				err = service.GenerateTTS(t.Context(), story.ID, tt.existing)
				if ttsSvc.calls != 1 {
					t.Fatalf("GenerateSpeech calls = %d, want 1", ttsSvc.calls)
				}
			} else {
				err = service.ProcessAudio(t.Context(), story.ID, inputPath)
			}
			if !errors.Is(err, audio.ErrSilent) {
				t.Fatalf("error = %v, want audio.ErrSilent", err)
			}
			if _, ok := errors.AsType[*apperrors.AudioError](err); !ok {
				t.Fatalf("error type = %T, want *apperrors.AudioError", err)
			}
			if repo.updateAudioCalls != 0 {
				t.Fatalf("UpdateAudio calls = %d, want 0", repo.updateAudioCalls)
			}
			entries, err := os.ReadDir(cfg.Audio.ProcessedPath)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.existing {
				if len(entries) != 0 {
					t.Fatalf("published directory = %v, want empty", entries)
				}
				return
			}
			// #nosec G304 - canonical story path inside t.TempDir
			got, err := os.ReadFile(finalPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, existingAudio) || len(entries) != 1 {
				t.Fatalf("existing audio changed or temporary output left behind: files = %v", entries)
			}
		})
	}
}

func silentStoryAudioFixture(t *testing.T) (string, string, []byte) {
	t.Helper()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	inputPath := filepath.Join(t.TempDir(), "silent.opus")
	// #nosec G204 - local ffmpeg binary and controlled test fixture arguments
	cmd := exec.CommandContext(t.Context(), ffmpegPath,
		"-f", "lavfi", "-i", "anullsrc=r=48000:cl=mono:d=1", "-y", inputPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create silent audio: %v; output: %s", err, output)
	}
	// #nosec G304 - fixture generated inside t.TempDir
	silentAudio, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	return ffmpegPath, inputPath, silentAudio
}
