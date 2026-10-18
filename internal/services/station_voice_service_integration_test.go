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

// A real MySQL commit must survive cancellation after the jingle is live.
func TestStationVoiceService_JinglePersistsAfterRequestCancel(t *testing.T) {
	f := newJingleDeleteFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.service.txManager = cancelAfterPublish{TxManager: repository.NewTxManager(f.db),
		t: t, finalPath: f.jinglePath, cancel: cancel}
	if err := f.service.ProcessJingle(ctx, f.stationVoice, f.input); err != nil {
		t.Fatalf("ProcessJingle = %v, want success after cancellation", err)
	}
	stored, err := f.service.GetByID(t.Context(), f.stationVoice.ID)
	want := utils.JingleFilename(f.stationVoice.StationID, f.stationVoice.VoiceID)
	if err != nil || stored.AudioFile != want {
		t.Fatalf("GetByID = %+v, %v; want audio_file %q", stored, err, want)
	}
	if ctx.Err() == nil {
		t.Fatal("request was not cancelled during publication")
	}
}

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
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	db := testutil.OpenIntegrationDB(t)
	cfg := &config.Config{Audio: config.AudioConfig{
		FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
	}}

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

func TestStationVoiceService_UpdateKeepsJingleWithItsPair(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newStationVoiceTestService(db)
	mixPoint := 4.5
	const omit = -1

	// station and voice index the two fixtures of each kind, or omit the field.
	tests := []struct {
		name       string
		jingle     fixtureJingle
		station    int
		voice      int
		wantLocked bool
	}{
		{name: "jingle blocks station change", jingle: pairJingle, station: 1, voice: omit, wantLocked: true},
		{name: "jingle blocks voice change", jingle: pairJingle, station: omit, voice: 1, wantLocked: true},
		{name: "jingle allows resending the pair", jingle: pairJingle, station: 0, voice: 0},
		{name: "jingle allows mix point change", jingle: pairJingle, station: omit, voice: omit},
		{name: "no jingle allows pair change", jingle: noJingle, station: 1, voice: 1},
		{name: "stale jingle allows resending the pair", jingle: staleJingle, station: 0, voice: 0},
		{name: "stale jingle blocks change to its pair", jingle: staleJingle, station: 1, voice: omit, wantLocked: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stations, voices, stationVoice := createStationVoiceFixture(t, db, tt.jingle)

			req := &UpdateStationVoiceRequest{MixPoint: &mixPoint}
			if tt.station != omit {
				req.StationID = &stations[tt.station].ID
			}
			if tt.voice != omit {
				req.VoiceID = &voices[tt.voice].ID
			}

			_, err := service.Update(t.Context(), stationVoice.ID, req)

			// Update never touches the jingle reference.
			want := stationVoice
			if tt.wantLocked {
				conflict, ok := errors.AsType[*apperrors.ConflictError](err)
				if !ok || conflict.Code != "stationvoice.jingle_locked" {
					t.Fatalf("Update() error = %v, want stationvoice.jingle_locked conflict", err)
				}
			} else {
				if err != nil {
					t.Fatalf("Update() error = %v", err)
				}
				want.MixPoint = mixPoint
				if req.StationID != nil {
					want.StationID = *req.StationID
				}
				if req.VoiceID != nil {
					want.VoiceID = *req.VoiceID
				}
			}

			var stored models.StationVoice
			if err := db.First(&stored, stationVoice.ID).Error; err != nil {
				t.Fatal(err)
			}
			if stored.StationID != want.StationID || stored.VoiceID != want.VoiceID ||
				stored.MixPoint != want.MixPoint || stored.AudioFile != want.AudioFile {
				t.Fatalf("stored row = %+v, want %d/%d with mix point %v and jingle %q",
					stored, want.StationID, want.VoiceID, want.MixPoint, want.AudioFile)
			}
		})
	}
}

func TestStationVoiceService_UpdateSeesUncommittedJingle(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := newStationVoiceTestService(db)
	stations, _, stationVoice := createStationVoiceFixture(t, db, noJingle)
	jingle := utils.JingleFilename(stationVoice.StationID, stationVoice.VoiceID)

	// An open transaction that has written the jingle holds the row lock, as
	// an upload does between its row update and commit.
	upload := db.Begin()
	if upload.Error != nil {
		t.Fatal(upload.Error)
	}
	t.Cleanup(func() { upload.Rollback() })
	if err := upload.Model(&models.StationVoice{}).Where("id = ?", stationVoice.ID).
		Update("audio_file", jingle).Error; err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := service.Update(t.Context(), stationVoice.ID, &UpdateStationVoiceRequest{StationID: &stations[1].ID})
		errc <- err
	}()
	// Let Update reach its read before the jingle commits. Without the lock it
	// reads no jingle and moves the pair once the upload commits.
	time.Sleep(200 * time.Millisecond)
	if err := upload.Commit().Error; err != nil {
		t.Fatal(err)
	}

	err := <-errc
	if conflict, ok := errors.AsType[*apperrors.ConflictError](err); !ok || conflict.Code != "stationvoice.jingle_locked" {
		t.Fatalf("Update() error = %v, want stationvoice.jingle_locked conflict", err)
	}
	var stored models.StationVoice
	if err := db.First(&stored, stationVoice.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.StationID != stationVoice.StationID || stored.AudioFile != jingle {
		t.Fatalf("stored row = %+v, want station %d with jingle %q", stored, stationVoice.StationID, jingle)
	}
}

func newStationVoiceTestService(db *gorm.DB) *StationVoiceService {
	return NewStationVoiceService(StationVoiceServiceDeps{
		TxManager:        repository.NewTxManager(db),
		StationVoiceRepo: repository.NewStationVoiceRepository(db),
		StationRepo:      repository.NewStationRepository(db),
		VoiceRepo:        repository.NewVoiceRepository(db),
	})
}

// fixtureJingle selects the jingle a station-voice fixture refers to.
type fixtureJingle int

const (
	noJingle fixtureJingle = iota
	// pairJingle is named after the fixture's own pair.
	pairJingle
	// staleJingle is named after the second station and first voice, as if
	// the row moved off that pair after its jingle was uploaded.
	staleJingle
)

// createStationVoiceFixture creates two stations and two voices, and links the
// first of each with mix point 1 and the given jingle.
func createStationVoiceFixture(t *testing.T, db *gorm.DB, jingle fixtureJingle) ([2]models.Station, [2]models.Voice, models.StationVoice) {
	t.Helper()
	stations := [2]models.Station{createNamedStation(t, db, t.Name()+"/a"), createNamedStation(t, db, t.Name()+"/b")}
	voices := [2]models.Voice{createNamedVoice(t, db, t.Name()+"/a"), createNamedVoice(t, db, t.Name()+"/b")}
	stationVoice := models.StationVoice{StationID: stations[0].ID, VoiceID: voices[0].ID, MixPoint: 1}
	switch jingle {
	case pairJingle:
		stationVoice.AudioFile = utils.JingleFilename(stations[0].ID, voices[0].ID)
	case staleJingle:
		stationVoice.AudioFile = utils.JingleFilename(stations[1].ID, voices[0].ID)
	}
	if err := db.Create(&stationVoice).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&stationVoice).Error; err != nil {
			t.Errorf("delete station-voice: %v", err)
		}
	})
	return stations, voices, stationVoice
}

// createNamedVoice inserts a voice with the given name and deletes it on
// cleanup.
func createNamedVoice(t *testing.T, db *gorm.DB, name string) models.Voice {
	t.Helper()
	voice := models.Voice{Name: name}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&voice).Error; err != nil {
			t.Errorf("delete voice: %v", err)
		}
	})
	return voice
}
