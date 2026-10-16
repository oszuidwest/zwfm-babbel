//go:build integration

package services

import (
	"context"
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

// interleavingRepository runs the other request before the first locks the story row.
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
			service := newAudioIntegrationService(t, db)
			repo := &interleavingRepository{storyRepository: service.storyRepo}
			service.storyRepo = repo
			story := createAudioIntegrationStory(t, db, nil)
			firstInput := audioFixture(t, service, "sine=frequency=440:duration=1")
			otherInput := audioFixture(t, service, tt.source)

			repo.during = func() {
				if err := service.ProcessAudio(t.Context(), story.ID, otherInput, nil); !errors.Is(err, tt.wantErr) {
					t.Fatalf("other request = %v, want %v", err, tt.wantErr)
				}
			}
			if err := service.ProcessAudio(t.Context(), story.ID, firstInput, nil); err != nil {
				t.Fatalf("first request = %v, want success", err)
			}

			finalPath := utils.StoryPath(service.config, story.ID)
			duration, err := service.audioSvc.Duration(t.Context(), finalPath)
			if err != nil {
				t.Fatal(err)
			}
			if math.Abs(duration-1) > 0.1 {
				t.Fatalf("published %.3f s, want the first request's 1 s audio", duration)
			}
			// duration_seconds is DECIMAL(8,2), rounded to hundredths by MySQL.
			state := audioStateOf(t, service, db, story.ID)
			if state.AudioFile != filepath.Base(finalPath) || math.Abs(state.Duration-duration) > 0.005 || len(state.Files) != 1 {
				t.Fatalf("state = %+v, want only %q, persisted with its %.3f s", state, filepath.Base(finalPath), duration)
			}
			assertUmaskMode(t, finalPath)
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
	// A directory in place of the published file makes the rename fail.
	if err := os.Mkdir(utils.StoryPath(service.config, story.ID), 0o750); err != nil {
		t.Fatal(err)
	}
	before := audioStateOf(t, service, db, story.ID)

	err := service.ProcessAudio(t.Context(), story.ID, audioFixture(t, service, "sine=frequency=880:duration=2"), nil)
	_, isDatabaseErr := errors.AsType[*apperrors.DatabaseError](err)
	if audioErr, ok := errors.AsType[*apperrors.AudioError](err); !ok || audioErr.Operation != "finalize" || isDatabaseErr {
		t.Fatalf("ProcessAudio = %v, want only a finalize audio error", err)
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
	// An event leaked into the shared database would hide in the next run's before.
	t.Cleanup(func() {
		if err := db.Where("entity_type = ? AND entity_id = ?", models.AuditEntityStory, missingID).Delete(&models.AuditEvent{}).Error; err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
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
			// Other connections see neither write before the rename and commit.
			if mid := audioStateOf(t, service, db, story.ID); mid.AudioFile != "" || len(mid.EventIDs) != 0 {
				t.Errorf("state visible before commit = %+v", mid)
			}
			if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
				t.Errorf("audio published before the row and audit writes returned: %v", err)
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

func TestStoryAudioCommitsAfterRequestCancel(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newAudioIntegrationService(t, db)
	story := createAudioIntegrationStory(t, db, nil)
	finalPath := utils.StoryPath(service.config, story.ID)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	service.txManager = cancelAfterPublish{TxManager: service.txManager, cancel: func() {
		if _, err := os.Stat(finalPath); err != nil {
			t.Errorf("request cancelled before the rename: %v", err)
		}
		cancel()
	}}

	if err := service.ProcessAudio(ctx, story.ID, audioFixture(t, service, "sine=frequency=440:duration=1"), nil); err != nil {
		t.Fatalf("ProcessAudio = %v, want success after the request was cancelled", err)
	}
	if ctx.Err() == nil {
		t.Fatal("request was not cancelled during the publication")
	}
	if after := audioStateOf(t, service, db, story.ID); after.AudioFile != utils.StoryFilename(story.ID) ||
		after.Duration <= 0 || len(after.EventIDs) != 1 || after.Files[utils.StoryFilename(story.ID)] == "" {
		t.Fatalf("published state = %+v, want the row, its audit event and the file", after)
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
	return lavfiFixture(t, s.config.Audio.FFmpegPath, source)
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
