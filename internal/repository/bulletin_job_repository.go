package repository

import (
	"context"
	"errors"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/gorm"
)

// ErrBulletinJobStateConflict means a job update found the job missing or not
// in the status the transition requires; the write was not applied.
var ErrBulletinJobStateConflict = errors.New("bulletin job state conflict")

// BulletinJobRepository stores durable bulletin generation jobs. A single
// worker goroutine owns every claimed job from claim to finalization; status
// transitions are still guarded (queued -> running -> succeeded/failed) so a
// lost commit response or misconfigured second instance can never overwrite a
// terminal job. The generic base is deliberately not embedded: unguarded
// helpers such as UpdateByID and Delete would bypass the status lifecycle.
type BulletinJobRepository struct {
	db   *gorm.DB
	base *GormRepository[models.BulletinJob]
}

// NewBulletinJobRepository uses db for job persistence and claims.
func NewBulletinJobRepository(db *gorm.DB) *BulletinJobRepository {
	return &BulletinJobRepository{db: db, base: NewGormRepository[models.BulletinJob](db)}
}

// GetByID retrieves a job by its primary key.
func (r *BulletinJobRepository) GetByID(ctx context.Context, id int64) (*models.BulletinJob, error) {
	return r.base.GetByID(ctx, id)
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

// ClaimNext marks the oldest queued job running and returns it, or nil when
// the queue is empty. Jobs at the attempt cap stay unclaimable; startup
// recovery terminally fails them.
func (r *BulletinJobRepository) ClaimNext(ctx context.Context, maxAttempts int) (*models.BulletinJob, error) {
	var job models.BulletinJob
	err := r.db.WithContext(ctx).
		Where("status = ? AND attempt < ?", models.BulletinJobQueued, maxAttempts).
		Order("id ASC").
		First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, ParseDBError(err)
	}

	now := time.Now()
	attempt := job.Attempt + 1
	result := r.db.WithContext(ctx).Model(&job).
		Where("status = ?", models.BulletinJobQueued).
		Updates(map[string]any{
			"status":     models.BulletinJobRunning,
			"attempt":    attempt,
			"started_at": now,
		})
	if err := checkedJobUpdate(result); err != nil {
		return nil, err
	}
	job.Status = models.BulletinJobRunning
	job.Attempt = attempt
	job.StartedAt = &now
	return &job, nil
}

// RequeueInterrupted returns jobs an unclean shutdown left running to the
// queue. It must run before the worker claims, so recovered state can never
// belong to a live attempt.
func (r *BulletinJobRepository) RequeueInterrupted(ctx context.Context) (int64, error) {
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("status = ?", models.BulletinJobRunning).
		Updates(map[string]any{
			"status":     models.BulletinJobQueued,
			"started_at": nil,
		})
	if result.Error != nil {
		return 0, ParseDBError(result.Error)
	}
	return result.RowsAffected, nil
}

// FailExhausted terminally fails queued jobs whose attempt budget is spent,
// so a job that keeps getting interrupted cannot retry forever.
func (r *BulletinJobRepository) FailExhausted(
	ctx context.Context,
	maxAttempts int,
	code, detail string,
) (int64, error) {
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("status = ? AND attempt >= ?", models.BulletinJobQueued, maxAttempts).
		Updates(map[string]any{
			"status":       models.BulletinJobFailed,
			"error_code":   code,
			"error_detail": detail,
			"completed_at": time.Now(),
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

// Complete records the generated bulletin and marks the running job
// successful. It participates in a transaction stored in ctx when present.
func (r *BulletinJobRepository) Complete(ctx context.Context, id int64, bulletinID int64) error {
	result := DBFromContext(ctx, r.db).WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ?", id, models.BulletinJobRunning).
		Updates(map[string]any{
			"status":       models.BulletinJobSucceeded,
			"bulletin_id":  bulletinID,
			"completed_at": time.Now(),
		})
	return checkedJobUpdate(result)
}

// Fail marks a running job failed with a client-safe error.
func (r *BulletinJobRepository) Fail(ctx context.Context, id int64, code, detail string) error {
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ?", id, models.BulletinJobRunning).
		Updates(map[string]any{
			"status":       models.BulletinJobFailed,
			"error_code":   code,
			"error_detail": detail,
			"completed_at": time.Now(),
		})
	return checkedJobUpdate(result)
}

// Release returns an interrupted running attempt to the queue during graceful
// shutdown.
func (r *BulletinJobRepository) Release(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Model(&models.BulletinJob{}).
		Where("id = ? AND status = ?", id, models.BulletinJobRunning).
		Updates(map[string]any{
			"status":     models.BulletinJobQueued,
			"started_at": nil,
		})
	return checkedJobUpdate(result)
}

func checkedJobUpdate(result *gorm.DB) error {
	if result.Error != nil {
		return ParseDBError(result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrBulletinJobStateConflict
	}
	return nil
}
