package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
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

// assertUmaskMode fails unless path has the mode the umask gives a new file.
func assertUmaskMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// os.Create applies the umask the same way FFmpeg does.
	ref, err := os.Create(filepath.Join(t.TempDir(), "ref.wav"))
	if err != nil {
		t.Fatal(err)
	}
	refInfo, err := ref.Stat()
	if err := errors.Join(err, ref.Close()); err != nil {
		t.Fatal(err)
	}
	if mode, want := info.Mode().Perm(), refInfo.Mode().Perm(); mode != want {
		t.Fatalf("published file mode = %v, want %v from the umask", mode, want)
	}
}

// failingTxManager fails the publication transaction: before fn when it
// cannot begin, or after fn succeeds when it cannot commit.
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
			service := newPublishAudioTestService(t)
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
			cause := errors.New("connection refused")
			service.txManager = failingTxManager{beginFails: tt.beginFails, err: cause}
			alerts := &capturingAlerter{}
			service.alerts = alerts
			const storyID = 99

			err := service.ProcessAudio(t.Context(), storyID, input, nil)
			dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
			if !ok || dbErr.Resource != "Story" || dbErr.Operation != apperrors.OpUpdate.String() || !errors.Is(err, cause) {
				t.Fatalf("ProcessAudio = %v, want a Story update database error caused by %v", err, cause)
			}
			finalPath := utils.StoryPath(service.config, storyID)
			if _, statErr := os.Stat(finalPath); (statErr == nil) != tt.wantPublished {
				t.Fatalf("published file: %v, want published = %v", statErr, tt.wantPublished)
			}
			if tt.wantPublished && !strings.Contains(errors.Unwrap(err).Error(), finalPath) {
				t.Fatalf("commit failure cause %q does not name %s", errors.Unwrap(err), finalPath)
			}
			wantAlerts := 0
			if tt.wantPublished {
				wantAlerts = 1
			}
			if len(alerts.events) != wantAlerts || len(alerts.resolved) != 0 {
				t.Fatalf("alerts = %+v, resolved = %v; want %d alerts and no recovery", alerts.events, alerts.resolved, wantAlerts)
			}
		})
	}
}

// A deadline error from the commit after the rename is reported with the live
// path, in an Error log and an immediate alert.
func TestStoryService_PublishAudioTimeoutAfterRenameReportsLiveFile(t *testing.T) {
	service := newPublishAudioTestService(t)
	input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
	cause := fmt.Errorf("commit: %w", context.DeadlineExceeded)
	service.txManager = failingTxManager{err: cause}
	alerts := &capturingAlerter{}
	service.alerts = alerts
	logs := captureLogs(t)
	const storyID = 99
	finalPath := utils.StoryPath(service.config, storyID)

	if err := service.ProcessAudio(t.Context(), storyID, input, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ProcessAudio = %v, want a deadline error", err)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "story:unrecorded-audio:99" ||
		alerts.events[0].RequiresThreshold || !strings.Contains(alerts.events[0].Details, finalPath) {
		t.Fatalf("alerts = %+v, want one immediate alert naming %s", alerts.events, finalPath)
	}
	for line := range bytes.Lines(logs.Bytes()) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		if record["level"] == "ERROR" && record["path"] == finalPath &&
			strings.Contains(fmt.Sprint(record["error"]), context.DeadlineExceeded.Error()) {
			return
		}
	}
	t.Fatalf("logs = %s, want an ERROR record naming %s and the timeout", logs, finalPath)
}

// cancelAfterPublish cancels the request inside the transaction, after fn
// renamed the audio onto finalPath and before the commit. It fails the test
// when the file is not live yet or the transaction has no deadline.
type cancelAfterPublish struct {
	repository.TxManager
	t         *testing.T
	finalPath string
	cancel    context.CancelFunc
}

func (m cancelAfterPublish) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Deadline(); !ok {
		m.t.Error("publication transaction has no deadline")
	}
	return m.TxManager.WithTransaction(ctx, func(txCtx context.Context) error {
		err := fn(txCtx)
		if _, statErr := os.Stat(m.finalPath); statErr != nil {
			m.t.Errorf("request cancelled before the rename: %v", statErr)
		}
		m.cancel()
		return err
	})
}

// contextTxManager commits only while its context is live, as database/sql
// rolls back a transaction whose context is done.
type contextTxManager struct{}

func (contextTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func TestStoryService_PublishAudioCommitsAfterRequestCancel(t *testing.T) {
	t.Parallel()
	service := newPublishAudioTestService(t)
	alerts := &capturingAlerter{}
	service.alerts = alerts
	const storyID = 99
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service.txManager = cancelAfterPublish{TxManager: contextTxManager{}, t: t,
		finalPath: utils.StoryPath(service.config, storyID), cancel: cancel}

	if err := service.ProcessAudio(ctx, storyID, lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1"), nil); err != nil {
		t.Fatalf("ProcessAudio = %v, want success after the request was cancelled", err)
	}
	if ctx.Err() == nil {
		t.Fatal("request was not cancelled during the publication")
	}
	if len(alerts.events) != 0 || !slices.Equal(alerts.resolved, []string{"story:unrecorded-audio:99"}) {
		t.Fatalf("alerts = %+v, resolved = %v; want only the unrecorded-audio recovery", alerts.events, alerts.resolved)
	}
}

// A request cancelled before the publication stops the conversion and leaves
// the published audio untouched.
func TestStoryService_PublishAudioConversionStopsOnRequestCancel(t *testing.T) {
	t.Parallel()
	service := newPublishAudioTestService(t)
	service.txManager = contextTxManager{}
	const storyID = 99
	input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, ok := errors.AsType[*apperrors.AudioError](service.ProcessAudio(ctx, storyID, input, nil)); !ok {
		t.Fatal("ProcessAudio after cancellation did not fail with an audio error")
	}
	if _, err := os.Stat(utils.StoryPath(service.config, storyID)); !os.IsNotExist(err) {
		t.Fatalf("published file: %v, want none", err)
	}
}

// newPublishAudioTestService returns a story service that converts with the
// local FFmpeg, publishes into a temporary directory and accepts every audio
// update. Callers set txManager.
func newPublishAudioTestService(t *testing.T) *StoryService {
	t.Helper()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	cfg := &config.Config{Audio: config.AudioConfig{
		FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
	}}
	return &StoryService{
		storyRepo: acceptingAudioRepository{}, audioSvc: audio.NewService(cfg, nil), config: cfg, alerts: notify.Discard,
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
