//go:build integration

package services

import (
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

func TestStationVoiceService_UpdateKeepsJingleWithItsPair(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	service := NewStationVoiceService(StationVoiceServiceDeps{
		TxManager:        repository.NewTxManager(db),
		StationVoiceRepo: repository.NewStationVoiceRepository(db),
		StationRepo:      repository.NewStationRepository(db),
		VoiceRepo:        repository.NewVoiceRepository(db),
	})
	mixPoint := 4.5
	const omit = -1

	// station and voice index the two fixtures of each kind, or omit the field.
	tests := []struct {
		name       string
		jingle     bool
		station    int
		voice      int
		wantLocked bool
	}{
		{name: "jingle blocks station change", jingle: true, station: 1, voice: omit, wantLocked: true},
		{name: "jingle blocks voice change", jingle: true, station: omit, voice: 1, wantLocked: true},
		{name: "jingle allows resending the pair", jingle: true, station: 0, voice: 0},
		{name: "jingle allows mix point change", jingle: true, station: omit, voice: omit},
		{name: "no jingle allows pair change", station: 1, voice: 1},
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

			want := models.StationVoice{
				StationID: stations[max(tt.station, 0)].ID,
				VoiceID:   voices[max(tt.voice, 0)].ID,
				MixPoint:  mixPoint,
			}
			if tt.wantLocked {
				conflict, ok := errors.AsType[*apperrors.ConflictError](err)
				if !ok || conflict.Code != "stationvoice.jingle_locked" {
					t.Fatalf("Update() error = %v, want stationvoice.jingle_locked conflict", err)
				}
				want = models.StationVoice{StationID: stations[0].ID, VoiceID: voices[0].ID, MixPoint: 1}
			} else if err != nil {
				t.Fatalf("Update() error = %v", err)
			}
			if tt.jingle {
				want.AudioFile = utils.JingleFilename(want.StationID, want.VoiceID)
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

// createStationVoiceFixture creates two stations and two voices, and links the
// first of each with mix point 1 and, if jingle is set, their jingle.
func createStationVoiceFixture(t *testing.T, db *gorm.DB, jingle bool) ([2]models.Station, [2]models.Voice, models.StationVoice) {
	t.Helper()
	stations := [2]models.Station{createNamedStation(t, db, t.Name()+"/a"), createNamedStation(t, db, t.Name()+"/b")}
	voices := [2]models.Voice{createNamedVoice(t, db, t.Name()+"/a"), createNamedVoice(t, db, t.Name()+"/b")}
	stationVoice := models.StationVoice{StationID: stations[0].ID, VoiceID: voices[0].ID, MixPoint: 1}
	if jingle {
		stationVoice.AudioFile = utils.JingleFilename(stations[0].ID, voices[0].ID)
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

func createNamedStation(t *testing.T, db *gorm.DB, name string) models.Station {
	t.Helper()
	station := models.Station{Name: name, MaxStoriesPerBlock: 5}
	if err := db.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&station).Error; err != nil {
			t.Errorf("delete station: %v", err)
		}
	})
	return station
}

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
