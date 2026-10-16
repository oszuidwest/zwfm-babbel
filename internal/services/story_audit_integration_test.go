//go:build integration

package services

import (
	"bytes"
	"errors"
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
		input := filepath.Join(t.TempDir(), "input.wav")
		// #nosec G204 - local FFmpeg and test-controlled arguments.
		if output, err := exec.CommandContext(t.Context(), ffmpeg, "-f", "lavfi", "-i", source, "-y", input).CombinedOutput(); err != nil {
			t.Fatalf("generate speech fixture: %v: %s", err, output)
		}
		data, err := os.ReadFile(input) // #nosec G304 - test temp file.
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
	assertTTSAuditActor(t, events, actor)
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
	assertTTSPublicationUnchanged(t, repo, published, dir, publishedAudio)
	if got := auditEvents(); len(got) != 1 || got[0].ID != events[0].ID {
		t.Fatalf("failed publication changed audit rows: %+v", got)
	}
}

func assertTTSAuditActor(t *testing.T, events []models.AuditEvent, actor int64) {
	t.Helper()
	if len(events) != 1 || events[0].Action != "tts" || events[0].UserID == nil || *events[0].UserID != actor {
		t.Fatalf("TTS events = %+v", events)
	}
}

func assertTTSPublicationUnchanged(
	t *testing.T, repo *repository.StoryRepository, published *models.Story, dir string, publishedAudio []byte,
) {
	t.Helper()
	publishedPath := filepath.Join(dir, published.AudioFile)
	after, err := repo.GetByID(t.Context(), published.ID)
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
