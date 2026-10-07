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
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local)
	bulletin := models.Bulletin{
		StationID: station.ID,
		Filename:  "latest-day.wav",
		CreatedAt: today.Add(-time.Second),
	}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&bulletin).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})

	maxAge := 48 * time.Hour
	if got, err := repo.GetLatest(t.Context(), station.ID, &maxAge); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetLatest() yesterday = %#v, %v; want ErrNotFound", got, err)
	}
	if got, err := repo.GetLatest(t.Context(), station.ID, nil); err != nil || got.ID != bulletin.ID {
		t.Fatalf("GetLatest() without maxAge = %#v, %v; want bulletin %d", got, err, bulletin.ID)
	}

	for _, test := range []struct {
		name      string
		createdAt time.Time
		maxAge    time.Duration
		wantFound bool
	}{
		{name: "local midnight included", createdAt: today, maxAge: maxAge, wantFound: true},
		{name: "current day within max age", createdAt: now, maxAge: maxAge, wantFound: true},
		{name: "age still enforced", createdAt: today, maxAge: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := db.Model(&bulletin).Update("created_at", test.createdAt).Error; err != nil {
				t.Fatalf("set bulletin time: %v", err)
			}
			got, err := repo.GetLatest(t.Context(), station.ID, &test.maxAge)
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
