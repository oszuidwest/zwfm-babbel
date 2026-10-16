//go:build integration

package services

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func TestBulletinJobService_EnqueueAfterStationDeletion(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station := createTestStation(t, db)
	// The URL's station existed when the handler checked it, then disappeared.
	if err := db.Delete(&station).Error; err != nil {
		t.Fatal(err)
	}
	service := &BulletinJobService{repo: repository.NewBulletinJobRepository(db)}
	_, err := service.Enqueue(t.Context(), station.ID)
	missing, ok := errors.AsType[*apperrors.NotFoundError](err)
	if !ok || missing.Resource != "Station" || missing.ID == nil || *missing.ID != station.ID {
		t.Fatalf("Enqueue() error = %v, want Station %d not found", err, station.ID)
	}
}

// A failed job logs once: at Warn for a station without stories, at Error
// otherwise. Claiming from the global queue needs a reset database without a
// running Babbel instance, as `make test-integration` provides.
func TestBulletinJobService_FailureLogLevel(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	tests := []struct {
		name      string
		err       error
		wantCode  string
		wantLevel string
	}{
		{name: "no stories", err: apperrors.NoStories(1), wantCode: apperrors.CodeBulletinNoStories, wantLevel: "WARN"},
		{name: "audio failure", err: apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg exit status 1")), wantCode: apperrors.CodeAudioProcessingFailed, wantLevel: "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			station := createTestStation(t, db)
			repo := repository.NewBulletinJobRepository(db)
			service := NewBulletinJobService(repo, NewBulletinService(BulletinServiceDeps{}),
				config.BulletinJobConfig{GenerationTimeout: time.Minute}, nil)
			service.generateBulletin = func(context.Context, int64, func(context.Context, int64) error) (int64, error) {
				return 0, tt.err
			}
			queued, err := service.Enqueue(t.Context(), station.ID)
			if err != nil {
				t.Fatalf("Enqueue() error = %v", err)
			}
			job, err := repo.ClaimNext(t.Context(), bulletinJobMaxAttempts)
			if err != nil || job == nil || job.ID != queued.ID {
				t.Fatalf("ClaimNext() = %#v, %v; want job %d", job, err, queued.ID)
			}

			logs := captureLogs(t)

			if err := service.processJob(t.Context(), job); err != nil {
				t.Fatalf("processJob() error = %v", err)
			}

			// Unmarshal rejects an empty buffer and a second record.
			var record map[string]any
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil ||
				record["level"] != tt.wantLevel || record["msg"] != "Bulletin generation job failed" {
				t.Fatalf("logs = %s, want one %s job failure record", logs.String(), tt.wantLevel)
			}
			stored, err := service.GetByID(t.Context(), job.ID)
			if err != nil || stored.Status != models.BulletinJobFailed || stored.ErrorCode != tt.wantCode {
				t.Fatalf("stored job = %#v, %v; want failed with %s", stored, err, tt.wantCode)
			}
		})
	}
}

// createTestStation inserts a station named after the test and deletes it on
// cleanup.
func createTestStation(t *testing.T, db *gorm.DB) models.Station {
	t.Helper()
	station := models.Station{Name: t.Name(), MaxStoriesPerBlock: 5}
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
