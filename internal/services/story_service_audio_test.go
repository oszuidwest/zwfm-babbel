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
			alerts := &capturingAlerter{}
			service := &StoryService{
				storyRepo: acceptingAudioRepository{}, txManager: failingTxManager{beginFails: tt.beginFails, err: cause},
				audioSvc: audio.NewService(cfg, nil), config: cfg, alerts: alerts,
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
			if wantAlerts := map[bool]int{false: 0, true: 1}[tt.wantPublished]; len(alerts.events) != wantAlerts {
				t.Fatalf("alerts = %+v, want %d", alerts.events, wantAlerts)
			}
		})
	}
}

// A publication that times out after the rename still names the live file:
// the handler's timeout branch logs only the DatabaseError, without its cause.
func TestStoryService_PublishAudioTimeoutAfterRenameReportsLiveFile(t *testing.T) {
	service, input := newPublishAudioTestService(t)
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
// renamed the audio onto the live path and before the commit.
type cancelAfterPublish struct {
	repository.TxManager
	cancel func()
}

func (m cancelAfterPublish) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	return m.TxManager.WithTransaction(ctx, func(txCtx context.Context) error {
		err := fn(txCtx)
		m.cancel()
		return err
	})
}

// contextTxManager commits only while its context is live, as database/sql
// rolls back a transaction whose context is done.
type contextTxManager struct{ committed bool }

func (m *contextTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if err := fn(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.committed = true
	return nil
}

// recordingAudioRepository records the audio update, which writes the row
// and its audit event.
type recordingAudioRepository struct {
	storyRepository
	updates []repository.StoryAudioUpdate
}

func (r *recordingAudioRepository) UpdateAudio(_ context.Context, _ int64, u repository.StoryAudioUpdate) error {
	r.updates = append(r.updates, u)
	return nil
}

func TestStoryService_PublishAudioCommitsAfterRequestCancel(t *testing.T) {
	t.Parallel()
	service, input := newPublishAudioTestService(t)
	repo := &recordingAudioRepository{}
	tx := &contextTxManager{}
	const storyID = 99
	finalPath := utils.StoryPath(service.config, storyID)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service.storyRepo = repo
	service.txManager = cancelAfterPublish{TxManager: tx, cancel: func() {
		if _, err := os.Stat(finalPath); err != nil {
			t.Errorf("request cancelled before the rename: %v", err)
		}
		cancel()
	}}
	actor := int64(307)

	if err := service.ProcessAudio(ctx, storyID, input, &actor); err != nil {
		t.Fatalf("ProcessAudio = %v, want success after the request was cancelled", err)
	}
	if ctx.Err() == nil || !tx.committed {
		t.Fatalf("request error = %v, committed = %v; want a cancelled request and a commit", ctx.Err(), tx.committed)
	}
	if len(repo.updates) != 1 || repo.updates[0].AudioFile != utils.StoryFilename(storyID) ||
		repo.updates[0].Action != models.AuditActionAudio || repo.updates[0].ActorUserID != &actor ||
		repo.updates[0].DurationSeconds <= 0 {
		t.Fatalf("audio updates = %+v", repo.updates)
	}
}

// newPublishAudioTestService returns a story service that publishes into a
// temporary directory, and a one-second tone to publish.
func newPublishAudioTestService(t *testing.T) (*StoryService, string) {
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
	}, lavfiFixture(t, ffmpegPath, "sine=frequency=440:duration=1")
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
