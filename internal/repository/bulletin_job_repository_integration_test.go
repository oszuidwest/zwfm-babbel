//go:build integration

package repository

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

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
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
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
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
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
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || first == nil {
		t.Fatalf("first ClaimNext() = %#v, %v", first, err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil {
		t.Fatalf("second ClaimNext() error = %v", err)
	}
	if second != nil {
		t.Fatalf("second claim = %#v, want nil while first job is leased", second)
	}

	if err := repo.Fail(t.Context(), first.ID, first.Attempt, "test.failure", "expected"); err != nil {
		t.Fatalf("Fail() error = %v", err)
	}
	third, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil {
		t.Fatalf("third ClaimNext() error = %v", err)
	}
	if third == nil || third.ID == first.ID {
		t.Fatalf("third claim = %#v, want the second queued job after the first finalized", third)
	}
}

func TestBulletinJobRepositoryIntegration_ConcurrentClaimsKeepOneActiveJobPerStation(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)
	repo := NewBulletinJobRepository(db)

	for range 2 {
		if _, err := repo.Create(t.Context(), station.ID, time.Now()); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	start := make(chan struct{})
	results := make([]*models.BulletinJob, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			<-start
			results[i], errs[i] = repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
		})
	}
	close(start)
	wg.Wait()

	claimed := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("ClaimNext() call %d error = %v", i, err)
		}
		if results[i] != nil {
			claimed++
			if results[i].StationID != station.ID {
				t.Fatalf("ClaimNext() call %d station = %d, want %d", i, results[i].StationID, station.ID)
			}
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent ClaimNext() calls claimed %d jobs, want exactly 1", claimed)
	}
}

func TestBulletinJobRepositoryIntegration_CompleteIsFenced(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || first == nil {
		t.Fatalf("first ClaimNext() = %#v, %v", first, err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("lease_until", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || second == nil {
		t.Fatalf("second ClaimNext() = %#v, %v", second, err)
	}

	bulletin := models.Bulletin{StationID: station.ID, Filename: "complete-fence-test.wav"}
	if err := db.Create(&bulletin).Error; err != nil {
		t.Fatalf("create bulletin: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Delete(&models.Bulletin{}, bulletin.ID).Error; err != nil {
			t.Errorf("delete bulletin: %v", err)
		}
	})

	// The reclaimed attempt must not record success; only the live attempt may.
	if err := repo.Complete(t.Context(), job.ID, first.Attempt, bulletin.ID); !errors.Is(err, ErrBulletinJobLeaseLost) {
		t.Fatalf("stale Complete() error = %v, want ErrBulletinJobLeaseLost", err)
	}
	if err := repo.Complete(t.Context(), job.ID, second.Attempt, bulletin.ID); err != nil {
		t.Fatalf("current Complete() error = %v", err)
	}

	var done models.BulletinJob
	if err := db.First(&done, job.ID).Error; err != nil {
		t.Fatalf("load completed job: %v", err)
	}
	if done.Status != models.BulletinJobSucceeded || done.BulletinID == nil || *done.BulletinID != bulletin.ID ||
		done.LeaseUntil != nil || done.CompletedAt == nil {
		t.Fatalf("completed job = %#v, want succeeded with bulletin %d and cleared lease", done, bulletin.ID)
	}
}

func TestBulletinJobRepositoryIntegration_ClaimOverlappingCompetingClaimKeepsOneActiveJob(t *testing.T) {
	// A competing transaction holds the oldest job's row lock while ClaimNext
	// runs, claims it, and commits. The station guard is best-effort
	// scheduling (see ClaimNext), so this test does not prove a stale
	// snapshot can never slip through; it pins the observed safe outcome
	// under the forced interleaving and, above all, regression-tests the
	// claim against deadlocks: a FOR UPDATE station guard failed here with
	// MySQL error 1213 in roughly half the runs.
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	first, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := repo.Create(t.Context(), station.ID, time.Now()); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB() error = %v", err)
	}
	tx, err := sqlDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("BeginTx() error = %v", err)
	}
	var held int64
	if err := tx.QueryRowContext(t.Context(),
		"SELECT id FROM bulletin_jobs WHERE id = ? FOR UPDATE", first.ID).Scan(&held); err != nil {
		t.Fatalf("lock oldest job: %v", err)
	}

	type claimResult struct {
		job *models.BulletinJob
		err error
	}
	results := make(chan claimResult, 1)
	go func() {
		job, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
		results <- claimResult{job: job, err: err}
	}()

	// Give the concurrent claim time to reach the held row lock before the
	// competing transaction claims the job and commits. The test user lacks
	// the PROCESS privilege, so the lock wait cannot be observed directly;
	// the assertion below holds regardless of whether the overlap was reached.
	time.Sleep(500 * time.Millisecond)
	if _, err := tx.ExecContext(t.Context(),
		"UPDATE bulletin_jobs SET status = ?, attempt = 1, lease_until = ?, started_at = ? WHERE id = ?",
		models.BulletinJobRunning, time.Now().Add(time.Minute), time.Now(), first.ID); err != nil {
		t.Fatalf("competing claim: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit competing claim: %v", err)
	}

	result := <-results
	if result.err != nil {
		t.Fatalf("overlapping ClaimNext() error = %v", result.err)
	}
	if result.job != nil {
		t.Fatalf("overlapping ClaimNext() = %#v, want nil while the station has a live job", result.job)
	}
}

func TestBulletinJobRepositoryIntegration_ExtendLeaseIsFenced(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	first, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || first == nil {
		t.Fatalf("first ClaimNext() = %#v, %v", first, err)
	}

	// An expired but unreclaimed lease still belongs to this attempt.
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("lease_until", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	if err := repo.ExtendLease(t.Context(), job.ID, first.Attempt, time.Hour); err != nil {
		t.Fatalf("ExtendLease() for the live attempt error = %v", err)
	}
	var extended models.BulletinJob
	if err := db.First(&extended, job.ID).Error; err != nil {
		t.Fatalf("load extended job: %v", err)
	}
	if extended.LeaseUntil == nil || !extended.LeaseUntil.After(time.Now()) {
		t.Fatalf("lease_until = %v, want re-armed into the future", extended.LeaseUntil)
	}

	// After a reclaim, the superseded attempt must stand down.
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("lease_until", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire lease again: %v", err)
	}
	second, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || second == nil || second.Attempt != first.Attempt+1 {
		t.Fatalf("reclaim ClaimNext() = %#v, %v; want attempt %d", second, err, first.Attempt+1)
	}
	if err := repo.ExtendLease(t.Context(), job.ID, first.Attempt, time.Hour); !errors.Is(err, ErrBulletinJobLeaseLost) {
		t.Fatalf("stale ExtendLease() error = %v, want ErrBulletinJobLeaseLost", err)
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

func TestBulletinJobRepositoryIntegration_ReleaseRequeues(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	claimed, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour)
	if err != nil || claimed == nil {
		t.Fatalf("ClaimNext() = %#v, %v", claimed, err)
	}
	oldQueueEntry := time.Now().Add(-time.Hour)
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", claimed.ID).
		UpdateColumn("updated_at", oldQueueEntry).Error; err != nil {
		t.Fatalf("age running job: %v", err)
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
	if !released.UpdatedAt.After(oldQueueEntry) {
		t.Fatalf("released job updated_at = %s, want after %s", released.UpdatedAt, oldQueueEntry)
	}

	reclaimed, err := repo.ClaimNext(t.Context(), time.Minute, 3, 15*time.Minute)
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
	if _, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour); err != nil {
		t.Fatalf("ClaimNext() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"lease_until": time.Now().Add(-time.Minute), "attempt": 3}).Error; err != nil {
		t.Fatalf("expire lease at cap: %v", err)
	}
	// Interrupted final attempts requeue at the cap.
	requeued, err := repo.Create(t.Context(), otherStation.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", requeued.ID).
		Update("attempt", 3).Error; err != nil {
		t.Fatalf("set requeued job at cap: %v", err)
	}

	// Jobs at the cap remain unclaimable before the sweep.
	if next, err := repo.ClaimNext(t.Context(), time.Minute, 3, time.Hour); err != nil || next != nil {
		t.Fatalf("ClaimNext() before sweep = %#v, %v; want nil, nil for jobs at cap", next, err)
	}
	kept, err := repo.Create(t.Context(), otherStation.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", kept.ID).
		Update("attempt", 2).Error; err != nil {
		t.Fatalf("set job below cap: %v", err)
	}

	_, err = repo.FailExhausted(t.Context(), 3, "internal.retries_exhausted", "expected")
	if err != nil {
		t.Fatalf("FailExhausted() error = %v", err)
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
	var belowCap models.BulletinJob
	if err := db.First(&belowCap, kept.ID).Error; err != nil {
		t.Fatalf("load job below cap: %v", err)
	}
	if belowCap.Status != models.BulletinJobQueued {
		t.Fatalf("job below cap status = %q, want queued", belowCap.Status)
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
		Update("updated_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age stale job: %v", err)
	}
	requeued, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", requeued.ID).
		Updates(map[string]any{"updated_at": time.Now().Add(-time.Hour), "attempt": 1}).Error; err != nil {
		t.Fatalf("age requeued job: %v", err)
	}

	_, err = repo.FailStaleQueued(t.Context(), 15*time.Minute, "internal.queue_timeout", "expected")
	if err != nil {
		t.Fatalf("FailStaleQueued() error = %v", err)
	}

	var kept models.BulletinJob
	if err := db.First(&kept, fresh.ID).Error; err != nil {
		t.Fatalf("load fresh job: %v", err)
	}
	if kept.Status != models.BulletinJobQueued {
		t.Fatalf("fresh job status = %q, want queued", kept.Status)
	}
	for _, id := range []int64{stale.ID, requeued.ID} {
		var terminal models.BulletinJob
		if err := db.First(&terminal, id).Error; err != nil {
			t.Fatalf("load stale job %d: %v", id, err)
		}
		if terminal.Status != models.BulletinJobFailed || terminal.ErrorCode != "internal.queue_timeout" || terminal.CompletedAt == nil {
			t.Fatalf("stale job %d = %#v, want failed with queue_timeout and completed_at set", id, terminal)
		}
	}
}

func TestBulletinJobRepositoryIntegration_StaleQueuedIsNotClaimable(t *testing.T) {
	db := openIntegrationDB(t)
	station := createBulletinJobStation(t, db)

	repo := NewBulletinJobRepository(db)
	job, err := repo.Create(t.Context(), station.ID, time.Now())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Update("updated_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatalf("age job: %v", err)
	}

	if stale, err := repo.ClaimNext(t.Context(), time.Minute, 3, 15*time.Minute); err != nil || stale != nil {
		t.Fatalf("ClaimNext() past queue SLA = %#v, %v; want nil, nil", stale, err)
	}

	if err := db.Model(&models.BulletinJob{}).Where("id = ?", job.ID).
		Updates(map[string]any{"attempt": 1, "updated_at": time.Now()}).Error; err != nil {
		t.Fatalf("mark job requeued: %v", err)
	}
	claimed, err := repo.ClaimNext(t.Context(), time.Minute, 3, 15*time.Minute)
	if err != nil || claimed == nil || claimed.ID != job.ID {
		t.Fatalf("ClaimNext() for requeued job = %#v, %v; want job %d", claimed, err, job.ID)
	}
}
