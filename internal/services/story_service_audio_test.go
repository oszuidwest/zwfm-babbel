package services

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestStoryService_RejectsSilenceAndKeepsExistingAudio(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	inputPath := lavfiFixture(t, ffmpegPath, "anullsrc=r=48000:cl=mono:d=1")
	// #nosec G304 - fixture generated inside t.TempDir
	silentAudio, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		run  func(ctx context.Context, s *StoryService, storyID int64) error
	}{
		{"upload", func(ctx context.Context, s *StoryService, storyID int64) error {
			return s.ProcessAudio(ctx, storyID, inputPath, nil)
		}},
		{"forced TTS", func(ctx context.Context, s *StoryService, storyID int64) error {
			return s.GenerateTTS(ctx, storyID, true, nil)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, ProcessedPath: t.TempDir(),
			}}
			story := storyForTTSTest("News bulletin")
			story.AudioFile = utils.StoryFilename(story.ID)
			finalPath := utils.StoryPath(cfg, story.ID)
			existingAudio := []byte("existing audio must stay intact")
			if err := os.WriteFile(finalPath, existingAudio, 0600); err != nil {
				t.Fatal(err)
			}
			// The fake's nil repository makes any database update panic.
			service := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, &fakeSpeechGenerator{data: silentAudio})
			service.config = cfg
			service.audioSvc = audio.NewService(cfg, nil)
			alerts := &capturingAlerter{}
			service.alerts = alerts

			err := tt.run(t.Context(), service, story.ID)
			if !errors.Is(err, audio.ErrSilent) {
				t.Fatalf("error = %v, want audio.ErrSilent", err)
			}
			if tt.name == "forced TTS" {
				assertSilentTTSFailure(t, err, alerts)
			}
			entries, err := os.ReadDir(cfg.Audio.ProcessedPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("processed files = %v, want only the existing audio", entries)
			}
			// #nosec G304 - canonical story path inside t.TempDir
			if got, err := os.ReadFile(finalPath); err != nil || !bytes.Equal(got, existingAudio) {
				t.Fatalf("existing audio = %q, %v; want %q", got, err, existingAudio)
			}
		})
	}
}

// lavfiFixture renders an FFmpeg lavfi source to a WAV file in a test temp
// directory and returns its path.
func lavfiFixture(t *testing.T, ffmpegPath, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.wav")
	// #nosec G204 - local ffmpeg binary and controlled test fixture arguments
	cmd := exec.CommandContext(t.Context(), ffmpegPath, "-f", "lavfi", "-i", source, "-y", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create audio fixture: %v; output: %s", err, output)
	}
	return path
}

// failingTxManager fails a transaction: before fn when it cannot begin, or
// after fn succeeds when it cannot commit.
type failingTxManager struct {
	beginFails bool
	err        error
}

func (m failingTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if !m.beginFails {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return m.err
}

// acceptingAudioRepository accepts every audio update.
type acceptingAudioRepository struct{ storyRepository }

func (acceptingAudioRepository) UpdateAudio(context.Context, int64, repository.StoryAudioUpdate) error {
	return nil
}

func TestStoryService_PublishAudioReportsTransactionFailuresAsDatabaseErrors(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	input := lavfiFixture(t, ffmpegPath, "sine=frequency=440:duration=1")
	for _, tt := range []struct {
		name          string
		beginFails    bool
		wantPublished bool
	}{
		{name: "begin", beginFails: true},
		{name: "commit", wantPublished: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			cause := errors.New("connection refused")
			service := &StoryService{
				storyRepo: acceptingAudioRepository{}, txManager: failingTxManager{beginFails: tt.beginFails, err: cause},
				audioSvc: audio.NewService(cfg, nil), config: cfg,
			}
			const storyID = 99

			err := service.ProcessAudio(t.Context(), storyID, input, nil)
			dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
			if !ok || dbErr.Resource != "Story" || dbErr.Operation != apperrors.OpUpdate.String() || !errors.Is(err, cause) {
				t.Fatalf("ProcessAudio = %v, want a Story update database error caused by %v", err, cause)
			}
			finalPath := utils.StoryPath(cfg, storyID)
			if _, statErr := os.Stat(finalPath); (statErr == nil) != tt.wantPublished {
				t.Fatalf("published file: %v, want published = %v", statErr, tt.wantPublished)
			}
			if tt.wantPublished && !strings.Contains(errors.Unwrap(err).Error(), finalPath) {
				t.Fatalf("commit failure cause %q does not name %s", errors.Unwrap(err), finalPath)
			}
		})
	}
}

func assertSilentTTSFailure(t *testing.T, err error, alerts *capturingAlerter) {
	t.Helper()
	upstream, ok := errors.AsType[*apperrors.UpstreamError](err)
	if !ok || upstream.Status != http.StatusBadGateway {
		t.Fatalf("error = %v, want UpstreamError with status 502", err)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "tts:upstream" || !alerts.events[0].RequiresThreshold {
		t.Fatalf("alerts = %+v, want tts:upstream requiring a threshold", alerts.events)
	}
	if len(alerts.resolved) != 0 {
		t.Fatalf("resolved alerts = %v, want none for silent audio", alerts.resolved)
	}
}
