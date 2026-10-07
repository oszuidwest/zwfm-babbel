//go:build integration

package services

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestGenerateTTSAuditAndFailedPublication(t *testing.T) {
	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Error(err)
		}
	})
	voice := models.Voice{Name: "Audit TTS voice", ElevenLabsVoiceID: new("test-voice")}
	if err := tx.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	story := models.Story{Title: "TTS audit", Text: "Test speech", VoiceID: &voice.ID, StartDate: time.Now(), EndDate: time.Now()}
	if err := tx.Create(&story).Error; err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "input.wav")
	// #nosec G204 - local FFmpeg and test-controlled arguments.
	if output, err := exec.CommandContext(t.Context(), ffmpeg, "-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-y", input).CombinedOutput(); err != nil {
		t.Fatalf("generate speech fixture: %v: %s", err, output)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe, ProcessedPath: dir}}
	repo := repository.NewStoryRepository(tx)
	service := &StoryService{
		storyRepo: repo, voiceRepo: repository.NewVoiceRepository(tx), audioSvc: audio.NewService(cfg, nil),
		ttsSvc: auditSpeechGenerator(data), ttsSettingsSvc: &fakeTTSSettingsGetter{settings: &models.TTSSettings{}},
		pronunciationInjector: NewPronunciationInjector(&fakePronunciationRuleLister{}), config: cfg, alerts: notify.Discard,
	}
	actor := int64(307)
	if err := service.GenerateTTS(t.Context(), story.ID, nil, false, &actor); err != nil {
		t.Fatal(err)
	}
	var events []models.AuditEvent
	if err := tx.Where("entity_type = ? AND entity_id = ?", "story", story.ID).Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != "tts" || events[0].UserID == nil || *events[0].UserID != actor {
		t.Fatalf("TTS events = %+v", events)
	}
	published, err := repo.GetByID(t.Context(), story.ID)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("audit unavailable")
	if err := tx.Callback().Create().Before("gorm:create").Register("test:reject_audit", func(db *gorm.DB) {
		if db.Statement.Table == "audit_events" {
			_ = db.AddError(sentinel)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := tx.Callback().Create().Remove("test:reject_audit"); err != nil {
			t.Error(err)
		}
	})
	if err := service.GenerateTTS(t.Context(), story.ID, nil, true, &actor); !errors.Is(err, sentinel) {
		t.Fatalf("failed TTS = %v", err)
	}
	after, err := repo.GetByID(t.Context(), story.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.AudioFile != published.AudioFile {
		t.Fatal("failed publication changed audio_file")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != published.AudioFile {
		t.Fatalf("failed publication removed old audio or left new audio: %v", files)
	}
	var count int64
	if err := tx.Model(&models.AuditEvent{}).Where("entity_type = ? AND entity_id = ?", "story", story.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed publication left audit rows: %d", count)
	}
}

type auditSpeechGenerator []byte

func (g auditSpeechGenerator) GenerateSpeech(context.Context, string, string, tts.Options) ([]byte, error) {
	return g, nil
}
