package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// The handler logs the rejection at the level of its class, so the service
// logs nothing. Log capture swaps the slog default, so this runs serially.
func TestStoryService_RejectsSilenceAndKeepsExistingAudio(t *testing.T) {
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
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
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(), TempPath: t.TempDir(),
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

			logs := testutil.CaptureLogs(t, slog.LevelInfo)
			err := tt.run(t.Context(), service, story.ID)
			if logs.Len() != 0 {
				t.Fatalf("logs = %s, want none", logs)
			}
			if !errors.Is(err, audio.ErrSilent) {
				t.Fatalf("error = %v, want audio.ErrSilent", err)
			}
			if tt.name == "forced TTS" {
				assertSilentTTSFailure(t, err, alerts)
			} else {
				assertSilentUploadRejected(t, err)
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

func TestUploadsRejectUndecodableAudioAndKeepExistingFiles(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	inputPath := filepath.Join(t.TempDir(), "not-audio.mp3")
	if err := os.WriteFile(inputPath, []byte("this is not audio\n"), 0600); err != nil {
		t.Fatal(err)
	}
	story := storyForTTSTest("News bulletin")
	stationVoice := &models.StationVoice{ID: 1, StationID: 2, VoiceID: 3}

	// The nil repositories make any database update panic.
	tests := []struct {
		field     string
		finalPath func(cfg *config.Config) string
		upload    func(ctx context.Context, cfg *config.Config) error
	}{
		{
			field:     "audio",
			finalPath: func(cfg *config.Config) string { return utils.StoryPath(cfg, story.ID) },
			upload: func(ctx context.Context, cfg *config.Config) error {
				service := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, nil)
				service.config = cfg
				service.audioSvc = audio.NewService(cfg, nil)
				return service.ProcessAudio(ctx, story.ID, inputPath, nil)
			},
		},
		{
			field: "jingle",
			finalPath: func(cfg *config.Config) string {
				return utils.JinglePath(cfg, stationVoice.StationID, stationVoice.VoiceID)
			},
			upload: func(ctx context.Context, cfg *config.Config) error {
				service := &StationVoiceService{config: cfg, audioSvc: audio.NewService(cfg, nil)}
				return service.ProcessJingle(ctx, stationVoice, inputPath)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			finalPath := tt.finalPath(cfg)
			existing := []byte("existing audio must stay intact")
			if err := os.WriteFile(finalPath, existing, 0600); err != nil {
				t.Fatal(err)
			}

			err := tt.upload(t.Context(), cfg)
			invalid, ok := errors.AsType[*apperrors.ValidationError](err)
			if !ok || len(invalid.Errors) != 1 || invalid.Errors[0].Field != tt.field ||
				invalid.Errors[0].Code != apperrors.CodeUndecodable {
				t.Fatalf("error = %v, want a %s field error with code %s", err, tt.field, apperrors.CodeUndecodable)
			}
			// The handler logs the cause's message.
			if !errors.Is(err, audio.ErrUndecodable) || !strings.Contains(invalid.Unwrap().Error(), audio.ErrUndecodable.Error()) {
				t.Fatalf("cause = %v, want the audio.ErrUndecodable message", invalid.Unwrap())
			}
			// #nosec G304 - canonical path inside t.TempDir
			if got, err := os.ReadFile(finalPath); err != nil || !bytes.Equal(got, existing) {
				t.Fatalf("existing file = %q, %v; want %q", got, err, existing)
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

// failingTxManager returns err instead of beginning (beginFails) or, after fn
// succeeds, instead of committing. With a nil err it runs fn like a working
// transaction.
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

// A silent upload is a client error: the handler logs it at Debug with the
// loudness measurements as its cause.
func assertSilentUploadRejected(t *testing.T, err error) {
	t.Helper()
	validation, ok := errors.AsType[*apperrors.ValidationError](err)
	if !ok || len(validation.Errors) != 1 ||
		validation.Errors[0].Field != "audio" || validation.Errors[0].Code != apperrors.CodeSilentAudio {
		t.Fatalf("error = %#v, want a ValidationError for audio/%s", err, apperrors.CodeSilentAudio)
	}
	if cause := validation.Unwrap(); cause == nil || !strings.Contains(cause.Error(), "input_tp") {
		t.Fatalf("validation cause = %v, want the loudness measurements", cause)
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
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
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
		FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(), TempPath: t.TempDir(),
	}}
	return &StoryService{
		storyRepo: acceptingAudioRepository{}, audioSvc: audio.NewService(cfg, nil), config: cfg, alerts: notify.Discard,
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
	// The handler logs the cause, so it must carry ffprobe's diagnostic.
	upstream, _ := errors.AsType[*apperrors.UpstreamError](err)
	if cause := upstream.Unwrap(); !errors.Is(cause, audio.ErrUndecodable) || !strings.Contains(cause.Error(), "Invalid data") {
		t.Fatalf("upstream cause = %v, want ffprobe's diagnostic", cause)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "tts:upstream" || !alerts.events[0].RequiresThreshold || len(alerts.resolved) != 0 {
		t.Fatalf("alerts = %+v, resolved = %v; want one thresholded upstream alert", alerts.events, alerts.resolved)
	}
	// #nosec G304 - canonical fixture in t.TempDir.
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, existing) {
		t.Fatalf("existing audio = %q, %v; want unchanged", data, err)
	}
}

func assertSilentTTSFailure(t *testing.T, err error, alerts *capturingAlerter) {
	t.Helper()
	upstream, ok := errors.AsType[*apperrors.UpstreamError](err)
	if !ok || upstream.Status != http.StatusBadGateway {
		t.Fatalf("error = %v, want UpstreamError with status 502", err)
	}
	// The handler logs the cause, so it must carry the loudness measurements.
	if cause := upstream.Unwrap(); cause == nil || !strings.Contains(cause.Error(), "input_tp") {
		t.Fatalf("upstream cause = %v, want the loudness measurements", cause)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "tts:upstream" || !alerts.events[0].RequiresThreshold {
		t.Fatalf("alerts = %+v, want tts:upstream requiring a threshold", alerts.events)
	}
	if len(alerts.resolved) != 0 {
		t.Fatalf("resolved alerts = %v, want none for silent audio", alerts.resolved)
	}
}
