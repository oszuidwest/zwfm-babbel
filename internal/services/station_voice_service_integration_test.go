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

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

func TestStationVoiceService_DeleteRacingFirstJingleUpload(t *testing.T) {
	f := newJingleDeleteFixture(t)

	// The first upload commits after Delete has read the row without a
	// jingle, just before its DELETE runs.
	uploaded := false
	if err := f.db.Callback().Delete().Before("gorm:delete").Register("test:upload_jingle", func(tx *gorm.DB) {
		if tx.Statement.Table != "station_voices" || uploaded {
			return
		}
		uploaded = true
		if err := f.service.ProcessJingle(t.Context(), f.stationVoice, f.input); err != nil {
			t.Errorf("ProcessJingle() during delete: %v", err)
		}
		if _, err := os.Stat(f.jinglePath); err != nil {
			t.Errorf("jingle after upload: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.service.Delete(t.Context(), f.stationVoice.ID); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if !uploaded {
		t.Fatal("upload did not run during the delete")
	}
	if _, err := os.Stat(f.jinglePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jingle after delete: %v, want removed", err)
	}

	// An upload that loaded the row before the delete finishes after it.
	err := f.service.ProcessJingle(t.Context(), f.stationVoice, f.input)
	if _, ok := errors.AsType[*apperrors.NotFoundError](err); !ok {
		t.Fatalf("ProcessJingle() after delete = %v, want not found", err)
	}
	if _, err := os.Stat(f.jinglePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jingle after late upload: %v, want removed", err)
	}
}

func TestStationVoiceService_DeleteKeepsReplacementJingle(t *testing.T) {
	f := newJingleDeleteFixture(t)

	// Right after the row's DELETE, another request tries to recreate the pair
	// and upload a jingle. Until the delete commits, that create is refused as
	// a duplicate; otherwise the delete's cleanup would remove the new jingle.
	// A refused request tries again right after the commit, before Delete
	// returns, so cleanup after the commit would remove that jingle too.
	tried := false
	var replaceErr error
	if err := f.db.Callback().Delete().After("gorm:delete").Register("test:replace_station_voice", func(tx *gorm.DB) {
		if tx.Statement.Table != "station_voices" || tried {
			return
		}
		tried = true
		replaceErr = f.replaceAndUploadJingle(t)
		if _, ok := errors.AsType[*apperrors.DuplicateError](replaceErr); ok {
			f.txManager.afterCommit = func() { replaceErr = f.replaceAndUploadJingle(t) }
		}
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.service.Delete(t.Context(), f.stationVoice.ID); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if !tried {
		t.Fatal("replacement did not run during the delete")
	}
	if replaceErr != nil {
		t.Fatalf("replace station-voice: %v", replaceErr)
	}
	if _, err := os.Stat(f.jinglePath); err != nil {
		t.Fatalf("replacement jingle after delete: %v, want kept", err)
	}
}

func TestStationVoiceService_DeleteRollsBackWhenJingleRemovalFails(t *testing.T) {
	f := newJingleDeleteFixture(t)

	// A non-empty directory at the jingle path makes os.Remove fail with an
	// error other than not-exist.
	if err := os.Mkdir(f.jinglePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.jinglePath, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := f.service.Delete(t.Context(), f.stationVoice.ID); err == nil {
		t.Fatal("Delete() = nil, want the removal error")
	}
	if _, err := f.service.GetByID(t.Context(), f.stationVoice.ID); err != nil {
		t.Fatalf("GetByID() after failed delete = %v, want the row kept", err)
	}
}

// jingleDeleteFixture is a station-voice without a jingle and a service whose
// jingles go to a temp directory.
type jingleDeleteFixture struct {
	db           *gorm.DB
	txManager    *afterCommitTxManager
	service      *StationVoiceService
	stationVoice *models.StationVoice
	jinglePath   string
	input        string
}

func newJingleDeleteFixture(t *testing.T) jingleDeleteFixture {
	t.Helper()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	db := testutil.OpenIntegrationDB(t)
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpegPath, ProcessedPath: t.TempDir()}}

	station := createTestStation(t, db)
	voice := models.Voice{Name: t.Name()}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	// Deleting the voice cascades to its station-voices.
	t.Cleanup(func() {
		if err := db.Delete(&voice).Error; err != nil {
			t.Errorf("delete voice: %v", err)
		}
	})

	txManager := &afterCommitTxManager{TxManager: repository.NewTxManager(db)}
	service := NewStationVoiceService(StationVoiceServiceDeps{
		TxManager:        txManager,
		StationVoiceRepo: repository.NewStationVoiceRepository(db),
		StationRepo:      repository.NewStationRepository(db),
		VoiceRepo:        repository.NewVoiceRepository(db),
		AudioSvc:         audio.NewService(cfg, nil),
		Config:           cfg,
	})
	stationVoice, err := service.Create(t.Context(), &CreateStationVoiceRequest{StationID: station.ID, VoiceID: voice.ID, MixPoint: 1})
	if err != nil {
		t.Fatal(err)
	}
	return jingleDeleteFixture{
		db:           db,
		txManager:    txManager,
		service:      service,
		stationVoice: stationVoice,
		jinglePath:   utils.JinglePath(cfg, station.ID, voice.ID),
		input:        lavfiFixture(t, ffmpegPath, "sine=frequency=440:duration=1"),
	}
}

// replaceAndUploadJingle creates the fixture's pair again and uploads its
// first jingle. The timeout fails a create that waits on a lock held by the
// calling goroutine before innodb_lock_wait_timeout would.
func (f jingleDeleteFixture) replaceAndUploadJingle(t *testing.T) error {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	replacement, err := f.service.Create(ctx, &CreateStationVoiceRequest{StationID: f.stationVoice.StationID, VoiceID: f.stationVoice.VoiceID, MixPoint: 1})
	if err != nil {
		return err
	}
	return f.service.ProcessJingle(ctx, replacement, f.input)
}

// afterCommitTxManager calls afterCommit once, right after the next
// transaction commits.
type afterCommitTxManager struct {
	repository.TxManager
	afterCommit func()
}

func (m *afterCommitTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	err := m.TxManager.WithTransaction(ctx, fn)
	if hook := m.afterCommit; err == nil && hook != nil {
		m.afterCommit = nil
		hook()
	}
	return err
}
