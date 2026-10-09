//go:build integration

package repository

import (
	"errors"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestBulletinRepositoryIntegration_GetLatestLocalDay(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)
	repo := NewBulletinRepository(db)
	today := startOfDay(time.Now())
	bulletin := models.Bulletin{StationID: station.ID, Filename: "latest-day.wav"}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&bulletin).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})

	twoDays, zero := 48*time.Hour, time.Duration(0)
	for _, test := range []struct {
		name      string
		createdAt time.Time
		maxAge    *time.Duration
		wantFound bool
	}{
		{name: "yesterday rejected", createdAt: today.Add(-time.Second), maxAge: &twoDays},
		{name: "yesterday without max age", createdAt: today.Add(-time.Second), wantFound: true},
		{name: "local midnight included", createdAt: today, maxAge: &twoDays, wantFound: true},
		{name: "age still enforced", createdAt: today, maxAge: &zero},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := db.Model(&bulletin).Update("created_at", test.createdAt).Error; err != nil {
				t.Fatalf("set bulletin time: %v", err)
			}
			got, err := repo.GetLatest(t.Context(), station.ID, test.maxAge)
			if test.wantFound {
				if err != nil || got.ID != bulletin.ID {
					t.Fatalf("GetLatest() = %#v, %v; want bulletin %d", got, err, bulletin.ID)
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Fatalf("GetLatest() = %#v, %v; want ErrNotFound", got, err)
			}
		})
	}
}
