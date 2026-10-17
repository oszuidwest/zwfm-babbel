//go:build integration

package services

import (
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

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
