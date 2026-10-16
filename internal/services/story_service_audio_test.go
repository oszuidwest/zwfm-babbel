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
	"sync"
	"sync/atomic"
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
	inputPath := filepath.Join(t.TempDir(), "silent.wav")
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

// gatedAudioRepository models UpdateAudio's transaction: the row lock
// serializes publication, and the row changes only when Publish succeeds.
// The first call waits for release before it writes.
type gatedAudioRepository struct {
	storyRepository
	reached, release chan struct{}
	gated            atomic.Bool

	mu              sync.Mutex
	audioFile       string
	durationSeconds float64
}

func (r *gatedAudioRepository) UpdateAudio(_ context.Context, _ int64, u repository.StoryAudioUpdate) error {
	if r.gated.CompareAndSwap(false, true) {
		close(r.reached)
		<-r.release
	}
	r.mu.Lock()
	defer r.mu.Unlock()
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
	fixture := func(source string) string {
		path := filepath.Join(t.TempDir(), "input.wav")
		// #nosec G204 - local ffmpeg binary and controlled test fixture arguments
		cmd := exec.CommandContext(t.Context(), ffmpegPath, "-f", "lavfi", "-i", source, "-y", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("create audio fixture: %v; output: %s", err, output)
		}
		return path
	}
	firstInput := fixture("sine=frequency=440:duration=1")

	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"other request fails", fixture("anullsrc=r=48000:cl=mono:d=1"), audio.ErrSilent},
		{"other request succeeds", fixture("sine=frequency=880:duration=2"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			repo := &gatedAudioRepository{reached: make(chan struct{}), release: make(chan struct{})}
			service := &StoryService{storyRepo: repo, audioSvc: audio.NewService(cfg, nil), config: cfg}
			const storyID = 99

			// Hold the first request between its conversion and publication.
			firstDone := make(chan error, 1)
			go func() { firstDone <- service.ProcessAudio(t.Context(), storyID, firstInput, nil) }()
			select {
			case <-repo.reached:
			case err := <-firstDone:
				t.Fatalf("first request finished before publishing: %v", err)
			}
			if err := service.ProcessAudio(t.Context(), storyID, tt.input, nil); !errors.Is(err, tt.wantErr) {
				t.Fatalf("other request = %v, want %v", err, tt.wantErr)
			}
			close(repo.release)
			if err := <-firstDone; err != nil {
				t.Fatalf("first request = %v, want success", err)
			}
			// The first request published last.
			assertOnlyPublishedAudio(t, service, repo, storyID, 1)
		})
	}
}

// assertOnlyPublishedAudio checks that the processed directory holds only the
// story's published file, and that the file and row both have wantSeconds.
func assertOnlyPublishedAudio(t *testing.T, service *StoryService, repo *gatedAudioRepository, storyID int64, wantSeconds float64) {
	t.Helper()
	finalPath := utils.StoryPath(service.config, storyID)
	duration, err := service.audioSvc.Duration(t.Context(), finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(duration-wantSeconds) > 0.1 || repo.audioFile != utils.StoryFilename(storyID) || repo.durationSeconds != duration {
		t.Fatalf("published %.3f s, row = %q with %.3f s; want %.0f s audio in both",
			duration, repo.audioFile, repo.durationSeconds, wantSeconds)
	}
	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("published file mode = %v, want 0644", mode)
	}
	entries, err := os.ReadDir(service.config.Audio.ProcessedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != utils.StoryFilename(storyID) {
		t.Fatalf("processed files = %v, want only the published audio", entries)
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
