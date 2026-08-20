//go:build integration

package repository

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// createBulletinJobStation creates a uniquely named station and registers
// cleanup of the station and its jobs.
func createBulletinJobStation(t *testing.T, db *gorm.DB) models.Station {
	t.Helper()
	station := models.Station{
		Name:               fmt.Sprintf("bulletin-job-%s-%d", t.Name(), time.Now().UnixNano()),
		MaxStoriesPerBlock: 5,
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
	return station
}

func TestBulletinJobRepositoryIntegration_ExpiredLeaseIsFenced(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3)
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
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3)
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
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	for range 2 {
		if _, err := repo.Create(t.Context(), station.ID, time.Now()); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3)
	if err != nil || first == nil {
		t.Fatalf("first ClaimNext() = %#v, %v", first, err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3)
	if err != nil {
		t.Fatalf("second ClaimNext() error = %v", err)
	}
	if second != nil {
		t.Fatalf("second claim = %#v, want nil while first job is leased", second)
	}

	// The queue must drain: once the running job finalizes, the next queued
	// job for the same station becomes claimable.
	if err := repo.Fail(t.Context(), first.ID, first.Attempt, "test.failure", "expected"); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
	third, err := repo.ClaimNext(t.Context(), time.Minute, 3)
	if err != nil {
		t.Fatalf("third ClaimNext() error = %v", err)
	}
	if third == nil || third.ID == first.ID {
		t.Fatalf("third claim = %#v, want the second queued job after the first finalized", third)
	}
}

func TestBulletinJobRepositoryIntegration_ReleaseRequeues(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	claimed, err := repo.ClaimNext(t.Context(), time.Minute, 3)
	if err != nil || claimed == nil {
		t.Fatalf("ClaimNext() = %#v, %v", claimed, err)
	}

	if err := repo.Release(t.Context(), claimed.ID, claimed.Attempt); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	var released models.BulletinJob
	if err := db.First(&released, job.ID).Error; err != nil {
		t.Fatalf("load released job: %v", err)
	}
	if released.Status != models.BulletinJobQueued || released.LeaseUntil != nil || released.StartedAt != nil {
		t.Fatalf("released job = %#v, want queued without lease or start time", released)
	}

	reclaimed, err := repo.ClaimNext(t.Context(), time.Minute, 3)
	if err != nil {
		t.Fatalf("reclaim ClaimNext() error = %v", err)
	}
	if reclaimed == nil || reclaimed.ID != job.ID || reclaimed.Attempt != 2 {
		t.Fatalf("reclaim = %#v, want job %d attempt 2", reclaimed, job.ID)
	}
}

func TestBulletinJobRepositoryIntegration_FailExhaustedAtAttemptCap(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)
	otherStation := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.ClaimNext(t.Context(), time.Minute, 3); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"lease_until": time.Now().Add(-time.Minute), "attempt": 3}).Error; err != nil {
		t.Fatalf("expire lease at cap: %v", err)
	}
	// A queued job released while its final attempt was interrupted also sits
	// at the cap and must be swept, not reclaimed.
	requeued, err := repo.Create(t.Context(), otherStation.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", requeued.ID).
		Update("attempt", 3).Error; err != nil {
		t.Fatalf("set requeued job at cap: %v", err)
	}

	// The claim predicate itself is the hard cap: expired or queued jobs at
	// the cap must never be claimable, even before the sweep runs.
	if next, err := repo.ClaimNext(t.Context(), time.Minute, 3); err != nil || next != nil {
		t.Fatalf("ClaimNext() before sweep = %#v, %v; want nil, nil for jobs at cap", next, err)
	}

	failed, err := repo.FailExhausted(t.Context(), 3, "internal.retries_exhausted", "expected")
	if err != nil {
		t.Fatalf("FailExhausted() error = %v", err)
	}
	if failed != 2 {
		t.Fatalf("FailExhausted() = %d, want 2", failed)
	}

	for _, id := range []int64{job.ID, requeued.ID} {
		var terminal models.BulletinJob
		if err := db.First(&terminal, id).Error; err != nil {
			t.Fatalf("load job %d: %v", id, err)
		}
		if terminal.Status != models.BulletinJobFailed || terminal.ErrorCode != "internal.retries_exhausted" || terminal.CompletedAt == nil {
			t.Fatalf("job %d = %#v, want failed with retries_exhausted and completed_at set", id, terminal)
		}
	}
	if next, err := repo.ClaimNext(t.Context(), time.Minute, 3); err != nil || next != nil {
		t.Fatalf("ClaimNext() after cap = %#v, %v; want nil, nil", next, err)
	}
}

func TestBulletinJobRepositoryIntegration_FailStaleQueued(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	fresh, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	stale, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", stale.ID).
		Update("created_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age stale job: %v", err)
	}
	// A job requeued after an interrupted attempt keeps its original
	// created_at but has attempt > 0; the queue-wait SLA only covers jobs no
	// worker ever picked up, so it must survive the sweep.
	requeued, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", requeued.ID).
		Updates(map[string]any{"created_at": time.Now().Add(-time.Hour), "attempt": 1}).Error; err != nil {
		t.Fatalf("age requeued job: %v", err)
	}

	failed, err := repo.FailStaleQueued(t.Context(), 15*time.Minute, "internal.queue_timeout", "expected")
	if err != nil {
		t.Fatalf("FailStaleQueued() error = %v", err)
	}
	if failed != 1 {
		t.Fatalf("FailStaleQueued() = %d, want 1", failed)
	}

	for name, id := range map[string]int64{"fresh": fresh.ID, "requeued": requeued.ID} {
		var kept models.BulletinJob
		if err := db.First(&kept, id).Error; err != nil {
			t.Fatalf("load %s job: %v", name, err)
		}
		if kept.Status != models.BulletinJobQueued {
			t.Fatalf("%s job status = %q, want queued", name, kept.Status)
		}
	}
}

func TestBulletinJobRepositoryIntegration_FindActiveCoalesces(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	today := time.Now()

	if none, err := repo.FindActive(t.Context(), station.ID, today); err != nil || none != nil {
		t.Fatalf("FindActive() on empty queue = %#v, %v; want nil, nil", none, err)
	}

	job, err := repo.Create(t.Context(), station.ID, today)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	found, err := repo.FindActive(t.Context(), station.ID, today)
	if err != nil || found == nil || found.ID != job.ID {
		t.Fatalf("FindActive() = %#v, %v; want queued job %d", found, err, job.ID)
	}

	if _, err := repo.ClaimNext(t.Context(), time.Minute, 3); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}
	running, err := repo.FindActive(t.Context(), station.ID, today)
	if err != nil || running == nil || running.ID != job.ID {
		t.Fatalf("FindActive() while running = %#v, %v; want job %d", running, err, job.ID)
	}

	if other, err := repo.FindActive(t.Context(), station.ID, today.AddDate(0, 0, 1)); err != nil || other != nil {
		t.Fatalf("FindActive() for another date = %#v, %v; want nil, nil", other, err)
	}

	if err := repo.Fail(t.Context(), job.ID, 1, "test.failure", "expected"); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
	if terminal, err := repo.FindActive(t.Context(), station.ID, today); err != nil || terminal != nil {
		t.Fatalf("FindActive() after terminal state = %#v, %v; want nil, nil", terminal, err)
	}
}
