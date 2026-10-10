//go:build integration

package services

import (
	"errors"
	"math"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestBulletinService_SaveWithDeletedStoryIsConflict(t *testing.T) {
	db := testutil.OpenIntegrationDB(t)
	station := models.Station{Name: t.Name(), MaxStoriesPerBlock: 5}
	if err := db.Create(&station).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&station).Error; err != nil {
			t.Errorf("delete station: %v", err)
		}
	})
	service := &BulletinService{
		txManager:    repository.NewTxManager(db),
		bulletinRepo: repository.NewBulletinRepository(db),
	}

	// The story was selected, then deleted before its bulletin link was written.
	_, err := service.saveBulletinToDatabase(t.Context(), saveBulletinParams{
		StationID:    station.ID,
		BulletinPath: t.Name() + ".wav",
		Stories:      []repository.BulletinStoryData{{Story: models.Story{ID: math.MaxInt32}}},
	}, nil)
	conflict, ok := errors.AsType[*apperrors.ConflictError](err)
	if !ok || conflict.Code != "bulletin.reference_missing" {
		t.Fatalf("saveBulletinToDatabase() error = %v, want bulletin.reference_missing conflict", err)
	}
}
