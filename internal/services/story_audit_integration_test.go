//go:build integration

package services

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

// openAuditIntegrationTx returns a transaction that is rolled back after the
// test, so services can write through nested savepoints without leaving data.
func openAuditIntegrationTx(t *testing.T) *gorm.DB {
	t.Helper()
	tx := testutil.OpenIntegrationDB(t).Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Error(err)
		}
	})
	return tx
}

// interleavingRepository runs the other request before the first starts its database transaction.
type interleavingRepository struct {
	storyRepository
	during func()
}

func (r *interleavingRepository) UpdateAudio(ctx context.Context, id int64, u repository.StoryAudioUpdate) error {
	if during := r.during; during != nil {
		r.during = nil
		during()
	}
	return r.storyRepository.UpdateAudio(ctx, id, u)
}

func TestStoryService_ConcurrentAudioRequestsPublishOwnFiles(t *testing.T) {
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
		{name: "other request fails", source: "anullsrc=r=48000:cl=mono:d=1", wantErr: audio.ErrSilent},
		{name: "other request succeeds", source: "sine=frequency=880:duration=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testutil.OpenIntegrationDB(t)
			otherInput := lavfiFixture(t, ffmpegPath, tt.source)
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			repo := &interleavingRepository{storyRepository: repository.NewStoryRepository(db)}
			service := &StoryService{storyRepo: repo, audioSvc: audio.NewService(cfg, nil), config: cfg}
			storyID, err := service.Create(t.Context(), idempotentCreate(t.Name(), newIdempotencyKey(t, db)))
			if err != nil {
				t.Fatal(err)
			}

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
			if math.Abs(duration-1) > 0.1 {
				t.Fatalf("published %.3f s, want the first request's 1 s audio", duration)
			}
			saved, err := repo.GetByID(t.Context(), storyID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.AudioFile != filepath.Base(finalPath) || saved.DurationSeconds == nil {
				t.Fatalf("persisted audio = %q, duration = %v; want %q and a duration",
					saved.AudioFile, saved.DurationSeconds, filepath.Base(finalPath))
			}
			// duration_seconds is DECIMAL(8,2), rounded to hundredths by MySQL.
			if math.Abs(*saved.DurationSeconds-duration) > 0.005 {
				t.Fatalf("persisted %.3f s, published %.3f s", *saved.DurationSeconds, duration)
			}
			assertUmaskMode(t, finalPath)
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

func TestGenerateTTSAuditAndFailedPublication(t *testing.T) {
	tx := openAuditIntegrationTx(t)
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	voice := models.Voice{Name: "Audit TTS voice", ElevenLabsVoiceID: new("test-voice")}
	if err := tx.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	story := models.Story{Title: "TTS audit", Text: "Test speech", VoiceID: &voice.ID, StartDate: models.Date(time.Now()), EndDate: models.Date(time.Now())}
	if err := tx.Create(&story).Error; err != nil {
		t.Fatal(err)
	}
	speech := func(source string) []byte {
		data, err := os.ReadFile(lavfiFixture(t, ffmpeg, source)) // #nosec G304 - test temp file.
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	speechGenerator := &fakeSpeechGenerator{data: speech("sine=frequency=440:duration=1")}
	dir := t.TempDir()
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe, ProcessedPath: dir}}
	repo := repository.NewStoryRepository(tx)
	service := &StoryService{
		storyRepo: repo, voiceRepo: repository.NewVoiceRepository(tx), audioSvc: audio.NewService(cfg, nil),
		ttsSvc: speechGenerator, ttsSettingsSvc: &fakeTTSSettingsGetter{settings: &models.TTSSettings{}},
		pronunciationInjector: NewPronunciationInjector(&fakePronunciationRuleLister{}), config: cfg, alerts: notify.Discard,
	}
	actor := int64(307)
	if err := service.GenerateTTS(t.Context(), story.ID, false, &actor); err != nil {
		t.Fatal(err)
	}
	auditEvents := func() []models.AuditEvent {
		var events []models.AuditEvent
		if err := tx.Where("entity_type = ? AND entity_id = ?", "story", story.ID).Find(&events).Error; err != nil {
			t.Fatal(err)
		}
		return events
	}
	events := auditEvents()
	if len(events) != 1 || events[0].Action != "tts" || events[0].UserID == nil || *events[0].UserID != actor {
		t.Fatalf("TTS events = %+v", events)
	}
	published, err := repo.GetByID(t.Context(), story.ID)
	if err != nil {
		t.Fatal(err)
	}
	publishedPath := filepath.Join(dir, published.AudioFile)
	publishedAudio, err := os.ReadFile(publishedPath) // #nosec G304 - test temp file.
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("audit unavailable")
	testutil.RejectAuditWrites(t, tx, func() error { return sentinel })
	speechGenerator.data = speech("sine=frequency=880:duration=2")
	if err := service.GenerateTTS(t.Context(), story.ID, true, &actor); !errors.Is(err, sentinel) {
		t.Fatalf("failed TTS = %v", err)
	}
	after, err := repo.GetByID(t.Context(), story.ID)
	if err != nil {
		t.Fatal(err)
	}
	if *after.DurationSeconds != *published.DurationSeconds {
		t.Fatalf("failed publication changed duration_seconds to %v", *after.DurationSeconds)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != published.AudioFile {
		t.Fatalf("failed publication removed old audio or left new audio: %v", files)
	}
	// The filename never changes, so only the contents show a premature publish.
	if current, err := os.ReadFile(publishedPath); err != nil || !bytes.Equal(current, publishedAudio) { // #nosec G304 - test temp file.
		t.Fatalf("failed publication replaced the published audio (err=%v)", err)
	}
	if got := auditEvents(); len(got) != 1 || got[0].ID != events[0].ID {
		t.Fatalf("failed publication changed audit rows: %+v", got)
	}
}

func TestTTSSettingsUpdateAuditFailure(t *testing.T) {
	tx := openAuditIntegrationTx(t)
	service := NewTTSSettingsService(repository.NewTTSSettingsRepository(tx), repository.NewTxManager(tx))
	before, err := service.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var auditErr error
	testutil.RejectAuditWrites(t, tx, func() error { return auditErr })
	prefix := before.TTSStylePrefix + " changed"
	update := func() error {
		_, err := service.Update(t.Context(), &UpdateTTSSettingsRequest{TTSStylePrefix: &prefix, ActorUserID: new(int64(307))})
		return err
	}

	auditErr = errors.New("audit unavailable")
	if err := update(); !errors.Is(err, auditErr) {
		t.Fatalf("update = %v", err)
	}
	after, err := service.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if after.TTSStylePrefix != before.TTSStylePrefix {
		t.Fatal("settings update survived failed audit")
	}

	// A missing audit table must not be reported as missing tts_settings,
	// whose recovery hint (001_complete_schema.sql) drops every table.
	auditErr = &mysql.MySQLError{Number: 1146, Message: "Table 'babbel.audit_events' doesn't exist"}
	var notInitialized *apperrors.NotInitializedError
	if err := update(); !errors.As(err, &notInitialized) ||
		notInitialized.Resource != "audit_events" || notInitialized.Hint != "apply migrations/013_audit_events.sql" {
		t.Fatalf("missing audit table = %#v", err)
	}
}
