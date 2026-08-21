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

// createBulletinJobStation prepares an isolated station. ClaimNext works on
// the global queue, so these tests need a reset database without a running
// Babbel instance, as `make test-integration` and CI provide; a polluted
// environment fails loudly rather than being cleaned up here.
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

func TestBulletinJobRepositoryIntegration_ClaimNextTakesOldestQueuedFirst(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	first, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	second, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	claimed, err := repo.ClaimNext(t.Context(), 3)
	if err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}
	if claimed == nil || claimed.ID != first.ID || claimed.Attempt != 1 ||
		claimed.Status != models.BulletinJobRunning || claimed.StartedAt == nil {
		t.Fatalf("first claim = %#v, want job %d running at attempt 1", claimed, first.ID)
	}

	next, err := repo.ClaimNext(t.Context(), 3)
	if err != nil {
		t.Fatalf("second ClaimNext() error = %v", err)
	}
	if next == nil || next.ID != second.ID {
		t.Fatalf("second claim = %#v, want job %d", next, second.ID)
	}

	empty, err := repo.ClaimNext(t.Context(), 3)
	if err != nil || empty != nil {
		t.Fatalf("ClaimNext() on empty queue = %#v, %v; want nil, nil", empty, err)
	}
}

// TestBulletinJobRepositoryIntegration_JobLifecycle walks one job from queued
// through running to succeeded, and verifies the terminal state rejects every
// further transition, e.g. after a Complete commit whose response was lost.
func TestBulletinJobRepositoryIntegration_JobLifecycle(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.ClaimNext(t.Context(), 3); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}

	bulletin := models.Bulletin{StationID: station.ID, Filename: "lifecycle-test.wav"}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&models.Bulletin{}, bulletin.ID).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})
	if err := repo.Complete(t.Context(), job.ID, bulletin.ID); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	for name, transition := range map[string]func() error{
		"Fail":     func() error { return repo.Fail(t.Context(), job.ID, "test.failure", "late") },
		"Release":  func() error { return repo.Release(t.Context(), job.ID) },
		"Complete": func() error { return repo.Complete(t.Context(), job.ID, bulletin.ID) },
	} {
		if err := transition(); !errors.Is(err, ErrBulletinJobStateConflict) {
			t.Fatalf("%s() on succeeded job error = %v, want ErrBulletinJobStateConflict", name, err)
		}
	}

	var stored models.BulletinJob
	if err := db.First(&stored, job.ID).Error; err != nil {
		t.Fatalf("load job: %v", err)
	}
	if stored.Status != models.BulletinJobSucceeded || stored.BulletinID == nil ||
		*stored.BulletinID != bulletin.ID || stored.CompletedAt == nil {
		t.Fatalf("job after rejected transitions = %#v, want untouched succeeded job with bulletin %d",
			stored, bulletin.ID)
	}
}

func TestBulletinJobRepositoryIntegration_FailRecordsClientSafeError(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.ClaimNext(t.Context(), 3); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}

	if err := repo.Fail(t.Context(), job.ID, "test.failure", "expected"); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}

	var failed models.BulletinJob
	if err := db.First(&failed, job.ID).Error; err != nil {
		t.Fatalf("load failed job: %v", err)
	}
	if failed.Status != models.BulletinJobFailed || failed.ErrorCode != "test.failure" ||
		failed.ErrorDetail != "expected" || failed.CompletedAt == nil {
		t.Fatalf("failed job = %#v, want failed with test.failure and completed_at set", failed)
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
	claimed, err := repo.ClaimNext(t.Context(), 3)
	if err != nil || claimed == nil {
		t.Fatalf("ClaimNext() = %#v, %v", claimed, err)
	}

	if err := repo.Release(t.Context(), claimed.ID); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	var released models.BulletinJob
	if err := db.First(&released, job.ID).Error; err != nil {
		t.Fatalf("load released job: %v", err)
	}
	if released.Status != models.BulletinJobQueued || released.StartedAt != nil {
		t.Fatalf("released job = %#v, want queued without start time", released)
	}

	reclaimed, err := repo.ClaimNext(t.Context(), 3)
	if err != nil {
		t.Fatalf("reclaim ClaimNext() error = %v", err)
	}
	if reclaimed == nil || reclaimed.ID != job.ID || reclaimed.Attempt != 2 {
		t.Fatalf("reclaim = %#v, want job %d attempt 2", reclaimed, job.ID)
	}
}

func TestBulletinJobRepositoryIntegration_RequeueInterruptedRecoversRunningJobs(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	interrupted, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.ClaimNext(t.Context(), 3); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}

	requeued, err := repo.RequeueInterrupted(t.Context())
	if err != nil {
		t.Fatalf("RequeueInterrupted() error = %v", err)
	}
	if requeued != 1 {
		t.Fatalf("RequeueInterrupted() = %d, want 1", requeued)
	}

	var recovered models.BulletinJob
	if err := db.First(&recovered, interrupted.ID).Error; err != nil {
		t.Fatalf("load recovered job: %v", err)
	}
	if recovered.Status != models.BulletinJobQueued || recovered.StartedAt != nil || recovered.Attempt != 1 {
		t.Fatalf("recovered job = %#v, want queued at attempt 1 without start time", recovered)
	}
}

func TestBulletinJobRepositoryIntegration_AttemptCapMakesJobsUnclaimable(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("attempt", 3).Error; err != nil {
		t.Fatalf("set job at cap: %v", err)
	}

	if next, err := repo.ClaimNext(t.Context(), 3); err != nil || next != nil {
		t.Fatalf("ClaimNext() at cap = %#v, %v; want nil, nil", next, err)
	}

	failed, err := repo.FailExhausted(t.Context(), 3, "internal.retries_exhausted", "expected")
	if err != nil {
		t.Fatalf("FailExhausted() error = %v", err)
	}
	if failed != 1 {
		t.Fatalf("FailExhausted() = %d, want 1", failed)
	}
	var terminal models.BulletinJob
	if err := db.First(&terminal, job.ID).Error; err != nil {
		t.Fatalf("load exhausted job: %v", err)
	}
	if terminal.Status != models.BulletinJobFailed || terminal.ErrorCode != "internal.retries_exhausted" ||
		terminal.CompletedAt == nil {
		t.Fatalf("exhausted job = %#v, want failed with retries_exhausted and completed_at set", terminal)
	}
}

func TestBulletinJobRepositoryIntegration_DeleteTerminalBeforeKeepsLiveJobs(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	newJob := func(updates map[string]any) *models.BulletinJob {
		job, err := repo.Create(t.Context(), station.ID, time.Now())
		if err != nil {
			t.Fatalf("Create() error = %v", err)
		}
		if len(updates) > 0 {
			if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).Updates(updates).Error; err != nil {
				t.Fatalf("prepare job %d: %v", job.ID, err)
			}
		}
		return job
	}
	oldTerminal := newJob(map[string]any{
		"status": models.BulletinJobFailed, "error_code": "test.failure",
		"completed_at": time.Now().Add(-2 * time.Hour),
	})
	recentTerminal := newJob(map[string]any{
		"status": models.BulletinJobFailed, "error_code": "test.failure",
		"completed_at": time.Now(),
	})
	// A pending job must survive the sweep even when it is old.
	oldQueued := newJob(map[string]any{"updated_at": time.Now().Add(-2 * time.Hour)})

	deleted, err := repo.DeleteTerminalBefore(t.Context(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("DeleteTerminalBefore() error = %v", err)
	}
	// The count is table-wide, so residue from other runs may inflate it; the
	// per-job assertions below carry the real guarantees.
	if deleted < 1 {
		t.Fatalf("DeleteTerminalBefore() = %d, want at least the old terminal job deleted", deleted)
	}

	if err := db.First(&models.BulletinJob{}, oldTerminal.ID).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("old terminal job lookup error = %v, want ErrRecordNotFound", err)
	}
	for _, id := range []int64{recentTerminal.ID, oldQueued.ID} {
		if err := db.First(&models.BulletinJob{}, id).Error; err != nil {
			t.Fatalf("job %d must survive the sweep: %v", id, err)
		}
	}
}
