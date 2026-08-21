package repository

import (
	"context"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ErrBulletinJobLeaseLost means another worker reclaimed or finalized a job.
var ErrBulletinJobLeaseLost = errors.New("bulletin job lease lost")

// BulletinJobRepository stores and atomically claims generation jobs.
type BulletinJobRepository struct {
	*GormRepository[models.BulletinJob]
}

// NewBulletinJobRepository uses db for job persistence and claims.
func NewBulletinJobRepository(db *gorm.DB) *BulletinJobRepository {
	return &BulletinJobRepository{GormRepository: NewGormRepository[models.BulletinJob](db)}
}

// Create queues a durable bulletin generation job.
func (r *BulletinJobRepository) Create(
	ctx context.Context,
	stationID int64,
	targetDate time.Time,
) (*models.BulletinJob, error) {
	job := &models.BulletinJob{
		StationID:  stationID,
		TargetDate: targetDate,
		Status:     models.BulletinJobQueued,
	}
	if err := DBFromContext(ctx, r.db).WithContext(ctx).Create(job).Error; err != nil {
		return nil, ParseDBError(err)
	}
	return job, nil
}

// ClaimNext leases the oldest queued or expired job under a row lock. It skips
// exhausted jobs, stale queued jobs, and stations with a live job.
func (r *BulletinJobRepository) ClaimNext(
	ctx context.Context,
	leaseDuration time.Duration,
	maxAttempts int,
	maxQueuedAge time.Duration,
) (*models.BulletinJob, error) {
	var claimed *models.BulletinJob
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		var job models.BulletinJob
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where(`
				(bulletin_jobs.status = ? OR (bulletin_jobs.status = ?
					AND (bulletin_jobs.lease_until IS NULL OR bulletin_jobs.lease_until < ?)))
				AND bulletin_jobs.attempt < ?
				AND NOT (bulletin_jobs.status = ? AND bulletin_jobs.updated_at < ?)
				AND NOT EXISTS (
					SELECT 1 FROM bulletin_jobs AS active
					WHERE active.station_id = bulletin_jobs.station_id
						AND active.id <> bulletin_jobs.id
						AND active.status = ?
						AND (active.lease_until IS NULL OR active.lease_until >= ?)
				)
			`, models.BulletinJobQueued, models.BulletinJobRunning, now, maxAttempts,
				models.BulletinJobQueued, now.Add(-maxQueuedAge), models.BulletinJobRunning, now).
			Order("bulletin_jobs.id ASC").
			First(&job).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		leaseUntil := now.Add(leaseDuration)
		attempt := job.Attempt + 1
		result := tx.Model(&job).Updates(map[string]any{
			"status":      models.BulletinJobRunning,
			"attempt":     attempt,
			"lease_until": leaseUntil,
			"started_at":  now,
		})
		if result.Error != nil {
			return result.Error
		}
		job.Status = models.BulletinJobRunning
		job.Attempt = attempt
		job.LeaseUntil = &leaseUntil
		job.StartedAt = &now
		claimed = &job
		return nil
	})
	if err != nil {
		return nil, ParseDBError(err)
	}
	return claimed, nil
}

// FailExhausted fails expired or requeued jobs at the attempt cap.
func (r *BulletinJobRepository) FailExhausted(
	ctx context.Context,
	maxAttempts int,
	code, detail string,
) (int64, error) {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("attempt >= ? AND (status = ? OR (status = ? AND (lease_until IS NULL OR lease_until < ?)))",
			maxAttempts, models.BulletinJobQueued, models.BulletinJobRunning, now).
		Updates(map[string]any{
			"status":       models.BulletinJobFailed,
			"error_code":   code,
			"error_detail": detail,
			"lease_until":  nil,
			"completed_at": now,
		})
	if result.Error != nil {
		return 0, ParseDBError(result.Error)
	}
	return result.RowsAffected, nil
}

// FailStaleQueued fails jobs that exceed maxQueuedAge after entering the queue.
func (r *BulletinJobRepository) FailStaleQueued(
	ctx context.Context,
	maxQueuedAge time.Duration,
	code, detail string,
) (int64, error) {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("status = ? AND updated_at < ?",
			models.BulletinJobQueued, now.Add(-maxQueuedAge)).
		Updates(map[string]any{
			"status":       models.BulletinJobFailed,
			"error_code":   code,
			"error_detail": detail,
			"completed_at": now,
		})
	if result.Error != nil {
		return 0, ParseDBError(result.Error)
	}
	return result.RowsAffected, nil
}

// DeleteTerminalBefore removes expired polling state; bulletins remain the audit trail.
func (r *BulletinJobRepository) DeleteTerminalBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("status IN ? AND completed_at < ?",
			[]models.BulletinJobStatus{models.BulletinJobSucceeded, models.BulletinJobFailed}, cutoff).
		Delete(&models.BulletinJob{})
	if result.Error != nil {
		return 0, ParseDBError(result.Error)
	}
	return result.RowsAffected, nil
}

// Complete records the generated bulletin and marks the leased attempt
// successful. It participates in a transaction stored in ctx when present.
func (r *BulletinJobRepository) Complete(ctx context.Context, id int64, attempt int, bulletinID int64) error {
	now := time.Now()
	result := DBFromContext(ctx, r.db).WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ? AND attempt = ?", id, models.BulletinJobRunning, attempt).
		Updates(map[string]any{
			"status":       models.BulletinJobSucceeded,
			"bulletin_id":  bulletinID,
			"lease_until":  nil,
			"completed_at": now,
		})
	return checkedJobUpdate(result)
}

// Fail marks a running job failed with a client-safe error.
func (r *BulletinJobRepository) Fail(ctx context.Context, id int64, attempt int, code, detail string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ? AND attempt = ?", id, models.BulletinJobRunning, attempt).
		Updates(map[string]any{
			"status":       models.BulletinJobFailed,
			"error_code":   code,
			"error_detail": detail,
			"lease_until":  nil,
			"completed_at": now,
		})
	return checkedJobUpdate(result)
}

// Release returns an interrupted attempt to the queue during graceful shutdown.
func (r *BulletinJobRepository) Release(ctx context.Context, id int64, attempt int) error {
	// Queued jobs use updated_at as their queue-entry timestamp.
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ? AND attempt = ?", id, models.BulletinJobRunning, attempt).
		Updates(map[string]any{
			"status":      models.BulletinJobQueued,
			"lease_until": nil,
			"started_at":  nil,
			"updated_at":  time.Now(),
		})
	return checkedJobUpdate(result)
}

func checkedJobUpdate(result *gorm.DB) error {
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	// Any other row count means another worker reclaimed or finalized the lease.
	if result.RowsAffected != 1 {
		return ErrBulletinJobLeaseLost
	}
	return nil
}
