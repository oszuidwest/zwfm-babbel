//go:build integration

package services

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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
	"gorm.io/gorm/clause"
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
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	voice := models.Voice{Name: t.Name(), ElevenLabsVoiceID: new("test-voice")}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&voice).Error; err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	story := createAudioIntegrationStory(t, db, &voice.ID)
	speech := func(source string) []byte {
		data, err := os.ReadFile(audioFixture(t, service, source)) // #nosec G304 - test temp file.
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	speechGenerator := &fakeSpeechGenerator{data: speech("sine=frequency=440:duration=1")}
	service.ttsSvc = speechGenerator
	service.ttsSettingsSvc = &fakeTTSSettingsGetter{settings: &models.TTSSettings{}}
	service.pronunciationInjector = NewPronunciationInjector(&fakePronunciationRuleLister{})
	actor := int64(307)
	if err := service.GenerateTTS(t.Context(), story.ID, false, &actor); err != nil {
		t.Fatal(err)
	}
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, story.ID).Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Action != models.AuditActionTTS || events[0].UserID == nil || *events[0].UserID != actor {
		t.Fatalf("TTS events = %+v", events)
	}
	published := audioStateOf(t, service, db, story.ID)

	sentinel := errors.New("audit unavailable")
	testutil.RejectAuditWrites(t, db, func() error { return sentinel })
	speechGenerator.data = speech("sine=frequency=880:duration=2")
	if err := service.GenerateTTS(t.Context(), story.ID, true, &actor); !errors.Is(err, sentinel) {
		t.Fatalf("failed TTS = %v", err)
	}
	// The filename never changes, so only the contents show a premature publish.
	if after := audioStateOf(t, service, db, story.ID); !reflect.DeepEqual(after, published) {
		t.Fatalf("failed publication changed state to %+v, want %+v", after, published)
	}
}

func TestStoryAudioNotPublishedWhenAuditFails(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	story := createAudioIntegrationStory(t, db, nil)
	actor := int64(307)
	upload := audioFixture(t, service, "sine=frequency=440:duration=1")
	// The repeated upload changes no column but still replaces what listeners hear.
	for range 2 {
		if err := service.ProcessAudio(t.Context(), story.ID, upload, &actor); err != nil {
			t.Fatal(err)
		}
	}
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, story.ID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || string(events[1].Changes) != "{}" {
		t.Fatalf("upload events = %+v", events)
	}
	for _, event := range events {
		if event.Action != models.AuditActionAudio || event.UserID == nil || *event.UserID != actor {
			t.Fatalf("upload event = %+v", event)
		}
	}
	published := audioStateOf(t, service, db, story.ID)

	sentinel := errors.New("audit unavailable")
	testutil.RejectAuditWrites(t, db, func() error { return sentinel })
	if err := service.ProcessAudio(t.Context(), story.ID, audioFixture(t, service, "sine=frequency=880:duration=2"), &actor); !errors.Is(err, sentinel) {
		t.Fatalf("ProcessAudio = %v, want audit error", err)
	}
	if after := audioStateOf(t, service, db, story.ID); !reflect.DeepEqual(after, published) {
		t.Fatalf("failed audit changed state to %+v, want %+v", after, published)
	}
}

func TestStoryAudioRenameFailureRollsBack(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	story := createAudioIntegrationStory(t, db, nil)
	if err := service.ProcessAudio(t.Context(), story.ID, audioFixture(t, service, "sine=frequency=440:duration=1"), nil); err != nil {
		t.Fatal(err)
	}
	// A directory in place of the published file makes the rename fail.
	finalPath := utils.StoryPath(service.config, story.ID)
	if err := os.Remove(finalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(finalPath, 0o750); err != nil {
		t.Fatal(err)
	}
	before := audioStateOf(t, service, db, story.ID)

	err := service.ProcessAudio(t.Context(), story.ID, audioFixture(t, service, "sine=frequency=880:duration=2"), nil)
	if audioErr, ok := errors.AsType[*apperrors.AudioError](err); !ok || audioErr.Operation != "finalize" {
		t.Fatalf("ProcessAudio = %v, want finalize audio error", err)
	}
	if after := audioStateOf(t, service, db, story.ID); !reflect.DeepEqual(after, before) {
		t.Fatalf("failed rename changed state to %+v, want %+v", after, before)
	}
}

func TestStoryAudioForMissingOrDeletedStoryKeepsPublishedFile(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	deleted := createAudioIntegrationStory(t, db, nil)
	if err := service.ProcessAudio(t.Context(), deleted.ID, audioFixture(t, service, "sine=frequency=440:duration=1"), nil); err != nil {
		t.Fatal(err)
	}
	if err := repository.NewStoryRepository(db).SoftDelete(t.Context(), deleted.ID, nil); err != nil {
		t.Fatal(err)
	}
	// A file can outlive its story row.
	missingID := int64(math.MaxInt64)
	if err := os.WriteFile(utils.StoryPath(service.config, missingID), []byte("orphaned audio"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := audioFixture(t, service, "sine=frequency=880:duration=2")
	for _, tt := range []struct {
		name    string
		id      int64
		wantErr func(error) bool
	}{
		{"deleted", deleted.ID, func(err error) bool { _, ok := errors.AsType[*repository.StoryDeletedError](err); return ok }},
		{"missing", missingID, func(err error) bool { _, ok := errors.AsType[*apperrors.NotFoundError](err); return ok }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := audioStateOf(t, service, db, tt.id)
			if err := service.ProcessAudio(t.Context(), tt.id, replacement, nil); !tt.wantErr(err) {
				t.Fatalf("ProcessAudio = %v", err)
			}
			if after := audioStateOf(t, service, db, tt.id); !reflect.DeepEqual(after, before) {
				t.Fatalf("rejected publication changed state to %+v, want %+v", after, before)
			}
		})
	}
}

func TestStoryAudioPublishedInsideTransaction(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	story := createAudioIntegrationStory(t, db, nil)
	finalPath := utils.StoryPath(service.config, story.ID)
	probed := false
	service.storyRepo = probingStoryRepository{
		StoryRepository: repository.NewStoryRepository(db),
		probe: func() {
			probed = true
			// Other connections see neither write before the rename and commit...
			if mid := audioStateOf(t, service, db, story.ID); mid.AudioFile != "" || len(mid.EventIDs) != 0 {
				t.Errorf("state visible before commit = %+v", mid)
			}
			if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
				t.Errorf("audio published before the row and audit writes returned: %v", err)
			}
			// ...and cannot write the row the audit snapshot locked.
			err := db.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate, Options: clause.LockingOptionsNoWait}).
				Table("stories").Where("id = ?", story.ID).Pluck("id", &[]int64{}).Error
			if mysqlErr, ok := errors.AsType[*mysql.MySQLError](err); !ok || mysqlErr.Number != 3572 {
				t.Errorf("locking read during publication = %v, want lock conflict", err)
			}
		},
	}
	if err := service.ProcessAudio(t.Context(), story.ID, audioFixture(t, service, "sine=frequency=440:duration=1"), nil); err != nil {
		t.Fatal(err)
	}
	if !probed {
		t.Fatal("probe did not run during the publication")
	}
	if after := audioStateOf(t, service, db, story.ID); after.AudioFile != utils.StoryFilename(story.ID) ||
		len(after.EventIDs) != 1 || after.Files[utils.StoryFilename(story.ID)] == "" {
		t.Fatalf("published state = %+v", after)
	}
}

// newAudioIntegrationService returns a story service that writes through db
// and publishes into a temporary directory.
func newAudioIntegrationService(t *testing.T, db *gorm.DB) *StoryService {
	t.Helper()
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe, ProcessedPath: t.TempDir()}}
	return &StoryService{
		storyRepo: repository.NewStoryRepository(db), voiceRepo: repository.NewVoiceRepository(db),
		audioSvc: audio.NewService(cfg, nil), config: cfg, alerts: notify.Discard, txManager: repository.NewTxManager(db),
	}
}

// audioFixture renders an FFmpeg lavfi source to a WAV file.
func audioFixture(t *testing.T, s *StoryService, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.wav")
	// #nosec G204 - local FFmpeg and test-controlled arguments.
	cmd := exec.CommandContext(t.Context(), s.config.Audio.FFmpegPath, "-f", "lavfi", "-i", source, "-y", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate audio fixture: %v: %s", err, output)
	}
	return path
}

// createAudioIntegrationStory creates a story without history and removes it
// and its history on cleanup.
func createAudioIntegrationStory(t *testing.T, db *gorm.DB, voiceID *int64) models.Story {
	t.Helper()
	story := models.Story{Title: t.Name(), Text: "Test speech", VoiceID: voiceID, StartDate: models.Date(time.Now()), EndDate: models.Date(time.Now())}
	if err := db.Create(&story).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, err := range []error{
			db.Unscoped().Delete(&models.Story{}, story.ID).Error,
			db.Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, story.ID).Delete(&models.AuditEvent{}).Error,
		} {
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	return story
}

// audioState is what a rejected or failed publication must leave unchanged.
type audioState struct {
	AudioFile string
	Duration  float64
	EventIDs  []int64
	Files     map[string]string // processed directory entry name to content hash
}

// audioStateOf reads committed state through db, outside any transaction.
func audioStateOf(t *testing.T, s *StoryService, db *gorm.DB, id int64) audioState {
	t.Helper()
	var row struct {
		AudioFile       *string
		DurationSeconds *float64
	}
	if err := db.Table("stories").Select("audio_file", "duration_seconds").Where("id = ?", id).Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	state := audioState{Files: map[string]string{}}
	if row.AudioFile != nil {
		state.AudioFile = *row.AudioFile
	}
	if row.DurationSeconds != nil {
		state.Duration = *row.DurationSeconds
	}
	if err := db.Model(&models.AuditEvent{}).Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, id).
		Order("id").Pluck("id", &state.EventIDs).Error; err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.config.Audio.ProcessedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			state.Files[entry.Name()] = "directory"
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.config.Audio.ProcessedPath, entry.Name())) // #nosec G304 - test temp file.
		if err != nil {
			t.Fatal(err)
		}
		state.Files[entry.Name()] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	return state
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
