//go:build integration

package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestBulletinJobRepositoryIntegration_ExpiredLeaseIsFenced(t *testing.T) {
	db := openIntegrationDB(t)
	station := models.Station{
		Name:               fmt.Sprintf("bulletin-job-lease-%d", time.Now().UnixNano()),
		MaxStoriesPerBlock: 5,
		PauseSeconds:       0,
	}
	if err := db.Create(&station).Error; err != nil {
		t.Fatalf("create station: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Where("station_id = ?", station.ID).Delete(&models.BulletinJob{}).Error; err != nil {
			t.Errorf("delete jobs: %v", err)
		}
		if err := db.Delete(&station).Error; err != nil {
			t.Errorf("delete station: %v", err)
		}
	})

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("first ClaimNext() error = %v", err)
	}
	if first == nil || first.ID != job.ID || first.Attempt != 1 {
		t.Fatalf("first claim = %#v, want job %d attempt 1", first, job.ID)
	}

	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("lease_until", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("second ClaimNext() error = %v", err)
	}
	if second == nil || second.ID != job.ID || second.Attempt != 2 {
		t.Fatalf("second claim = %#v, want job %d attempt 2", second, job.ID)
	}

	if err := repo.Fail(t.Context(), job.ID, first.Attempt, "stale", "stale"); !errors.Is(err, ErrBulletinJobLeaseLost) {
		t.Fatalf("stale Fail() error = %v, want ErrBulletinJobLeaseLost", err)
	}
	if err := repo.Fail(t.Context(), job.ID, second.Attempt, "test.failure", "expected"); err != nil {
		t.Fatalf("current Fail() error = %v", err)
	}
}

func TestBulletinJobRepositoryIntegration_OneActiveJobPerStation(t *testing.T) {
	db := openIntegrationDB(t)
	station := models.Station{
		Name:               fmt.Sprintf("bulletin-job-station-%d", time.Now().UnixNano()),
		MaxStoriesPerBlock: 5,
		PauseSeconds:       0,
	}
	if err := db.Create(&station).Error; err != nil {
		t.Fatalf("create station: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Where("station_id = ?", station.ID).Delete(&models.BulletinJob{}).Error
		_ = db.Delete(&station).Error
	})

	repo := NewBulletinJobRepository(db)
	for range 2 {
		if _, err := repo.Create(t.Context(), station.ID, time.Now()); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute)
	if err != nil || first == nil {
		t.Fatalf("first ClaimNext() = %#v, %v", first, err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute)
	if err != nil {
		t.Fatalf("second ClaimNext() error = %v", err)
	}
	if second != nil {
		t.Fatalf("second claim = %#v, want nil while first job is leased", second)
	}
}
