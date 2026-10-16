package services

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

// interleavingRepository records the published row values and runs during
// inside the first UpdateAudio call, between that request's conversion and
// its publication.
type interleavingRepository struct {
	storyRepository
	during          func()
	audioFile       string
	durationSeconds float64
}

func (r *interleavingRepository) UpdateAudio(_ context.Context, _ int64, u repository.StoryAudioUpdate) error {
	if during := r.during; during != nil {
		r.during = nil
		during()
	}
	if err := u.Publish(); err != nil {
		return err
	}
	r.audioFile, r.durationSeconds = u.AudioFile, u.DurationSeconds
	return nil
}

func TestStoryService_ConcurrentAudioRequestsPublishOwnFiles(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	firstInput := lavfiFixture(t, ffmpegPath, "sine=frequency=440:duration=1")

	tests := []struct {
		name    string
		source  string
		wantErr error
	}{
		{"other request fails", "anullsrc=r=48000:cl=mono:d=1", audio.ErrSilent},
		{"other request succeeds", "sine=frequency=880:duration=2", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			otherInput := lavfiFixture(t, ffmpegPath, tt.source)
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			repo := &interleavingRepository{}
			service := &StoryService{storyRepo: repo, audioSvc: audio.NewService(cfg, nil), config: cfg}
			const storyID = 99

			// Run the other request while the first waits to publish, so the
			// first publishes last.
			repo.during = func() {
				if err := service.ProcessAudio(t.Context(), storyID, otherInput, nil); !errors.Is(err, tt.wantErr) {
					t.Fatalf("other request = %v, want %v", err, tt.wantErr)
				}
			}
			if err := service.ProcessAudio(t.Context(), storyID, firstInput, nil); err != nil {
				t.Fatalf("first request = %v, want success", err)
			}

			finalPath := utils.StoryPath(cfg, storyID)
			duration, err := service.audioSvc.Duration(t.Context(), finalPath)
			if err != nil {
				t.Fatal(err)
			}
			publishedFirst := math.Abs(duration-1) <= 0.1
			rowMatchesFile := repo.audioFile == utils.StoryFilename(storyID) && repo.durationSeconds == duration
			if !publishedFirst || !rowMatchesFile {
				t.Fatalf("published %.3f s, row = %q with %.3f s; want the first request's 1 s audio in both",
					duration, repo.audioFile, repo.durationSeconds)
			}
			info, err := os.Stat(finalPath)
			if err != nil {
				t.Fatal(err)
			}
			if mode := info.Mode().Perm(); mode != 0o644 {
				t.Fatalf("published file mode = %v, want 0644", mode)
			}
			entries, err := os.ReadDir(cfg.Audio.ProcessedPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("processed files = %v, want only the published audio", entries)
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
