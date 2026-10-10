//go:build integration

package services

import (
	"errors"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestBulletinJobService_EnqueueAfterStationDeletion(t *testing.T) {
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
