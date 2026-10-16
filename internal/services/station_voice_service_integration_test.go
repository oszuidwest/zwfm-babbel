//go:build integration

package services

import (
	"errors"
	"os"
	"os/exec"
	"testing"

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
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	db := testutil.OpenIntegrationDB(t)
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpegPath, ProcessedPath: t.TempDir()}}
	service, stationVoice := createJingleStationVoice(t, db, cfg)
	input := lavfiFixture(t, ffmpegPath, "sine=frequency=440:duration=1")
	jinglePath := utils.JinglePath(cfg, stationVoice.StationID, stationVoice.VoiceID)

	// The first upload commits after Delete has read the row without a
	// jingle, just before its DELETE runs.
	uploaded := false
	if err := db.Callback().Delete().Before("gorm:delete").Register("test:upload_jingle", func(tx *gorm.DB) {
		if tx.Statement.Table != "station_voices" || uploaded {
			return
		}
		uploaded = true
		if err := service.ProcessJingle(t.Context(), stationVoice, input); err != nil {
			t.Errorf("ProcessJingle() during delete: %v", err)
		}
		if _, err := os.Stat(jinglePath); err != nil {
			t.Errorf("jingle after upload: %v", err)
		}
	}); err != nil {
		t.Fatal(err)
	}

	if err := service.Delete(t.Context(), stationVoice.ID); err != nil {
		t.Fatalf("Delete() = %v", err)
	}
	if !uploaded {
		t.Fatal("upload did not run during the delete")
	}
	if _, err := os.Stat(jinglePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jingle after delete: %v, want removed", err)
	}

	// An upload that loaded the row before the delete publishes after it.
	err = service.ProcessJingle(t.Context(), stationVoice, input)
	if _, ok := errors.AsType[*apperrors.NotFoundError](err); !ok {
		t.Fatalf("ProcessJingle() after delete = %v, want not found", err)
	}
	if _, err := os.Stat(jinglePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("jingle after late upload: %v, want removed", err)
	}
}

// createJingleStationVoice returns a service storing jingles per cfg and a new
// station-voice without a jingle.
func createJingleStationVoice(t *testing.T, db *gorm.DB, cfg *config.Config) (*StationVoiceService, *models.StationVoice) {
	t.Helper()
	station := createTestStation(t, db)
	voice := models.Voice{Name: t.Name()}
	if err := db.Create(&voice).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, err := range []error{
			db.Where("voice_id = ?", voice.ID).Delete(&models.StationVoice{}).Error,
			db.Delete(&voice).Error,
		} {
			if err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})

	service := NewStationVoiceService(StationVoiceServiceDeps{
		TxManager:        repository.NewTxManager(db),
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
	return service, stationVoice
}
