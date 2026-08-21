package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	// Poll for cross-replica enqueues and expired leases; local enqueues wake workers.
	bulletinJobPollInterval  = 5 * time.Second
	bulletinJobUpdateTimeout = 5 * time.Second

	// Claims exclude terminal candidates between sweeps.
	bulletinJobSweepInterval = time.Minute

	// Bound crash-loop retries so one job cannot starve its station.
	bulletinJobMaxAttempts = 3

	jobDetailGenerationFailed = "Bulletin generation failed"

	claimAlertKey = "bulletin-jobs:claim"
)

// BulletinJobService queues, processes, and exposes durable generation jobs.
type BulletinJobService struct {
	repo      *repository.BulletinJobRepository
	locks     *repository.NamedLockManager
	bulletins *BulletinService
	alerts    notify.Alerter
	cfg       config.BulletinJobConfig
	lastSweep atomic.Int64
	wake      chan struct{}
	done      chan struct{}
	cancel    context.CancelFunc
	startOnce sync.Once
}

// NewBulletinJobService returns a stopped worker; cfg must be validated.
func NewBulletinJobService(
	repo *repository.BulletinJobRepository,
	locks *repository.NamedLockManager,
	bulletins *BulletinService,
	cfg config.BulletinJobConfig,
	alerts notify.Alerter,
) *BulletinJobService {
	return &BulletinJobService{
		repo:      repo,
		locks:     locks,
		bulletins: bulletins,
		alerts:    notify.OrDiscard(alerts),
		cfg:       cfg,
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
}

// Start launches configured workers; extra workers add cross-station throughput.
func (s *BulletinJobService) Start() {
	s.startOnce.Do(func() {
		workerCtx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		var wg sync.WaitGroup
		for range s.cfg.Workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.run(workerCtx)
			}()
		}
		go func() {
			wg.Wait()
			close(s.done)
		}()
	})
}

// Stop cancels active generation and waits for all workers to exit.
func (s *BulletinJobService) Stop(ctx context.Context) error {
	if s.cancel == nil {
		return nil
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Enqueue returns an active station-date job or persists and wakes a new one.
func (s *BulletinJobService) Enqueue(
	ctx context.Context,
	stationID int64,
	targetDate time.Time,
) (*models.BulletinJob, error) {
	// Avoid the cross-replica lock when the job is already visible.
	existing, err := s.repo.FindActive(ctx, stationID, targetDate)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin job", apperrors.OpQuery, err)
	}
	if existing != nil {
		return existing, nil
	}

	// Preserve DeadlineExceeded so HTTP mapping returns 504.
	release, err := s.locks.LockEnqueue(ctx, stationID)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin job", apperrors.OpCreate, err)
	}
	defer release()

	existing, err = s.repo.FindActive(ctx, stationID, targetDate)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin job", apperrors.OpQuery, err)
	}
	if existing != nil {
		return existing, nil
	}

	job, err := s.repo.Create(ctx, stationID, targetDate)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin job", apperrors.OpCreate, err)
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return job, nil
}

// GetByID returns the current polling representation for a job.
func (s *BulletinJobService) GetByID(ctx context.Context, id int64) (*models.BulletinJob, error) {
	job, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoErrorWithID("Bulletin job", id, apperrors.OpQuery, err)
	}
	return job, nil
}

func (s *BulletinJobService) run(ctx context.Context) {
	ticker := time.NewTicker(bulletinJobPollInterval)
	defer ticker.Stop()

	for {
		err := s.processQueued(ctx)
		switch {
		case err == nil:
			s.alerts.Resolve(ctx, claimAlertKey, "Bulletin job worker recovered",
				"The worker is claiming and processing jobs again.")
		case !errors.Is(err, context.Canceled):
			logger.Error("Bulletin job worker failed to claim work", "error", err)
			s.alerts.Alert(ctx, notify.Event{
				Key:               claimAlertKey,
				Summary:           "Bulletin job worker cannot claim work",
				Details:           err.Error(),
				RequiresThreshold: true,
			})
		}

		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

func (s *BulletinJobService) processQueued(ctx context.Context) error {
	if err := s.sweepIfDue(ctx); err != nil {
		return err
	}
	// Leave time to persist the result before another worker may reclaim the lease.
	leaseFor := s.cfg.GenerationTimeout + (2 * bulletinJobUpdateTimeout)
	for ctx.Err() == nil {
		job, err := s.repo.ClaimNext(ctx, leaseFor, bulletinJobMaxAttempts, s.cfg.QueueTimeout)
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}
		// Wake an idle worker for remaining queued jobs.
		select {
		case s.wake <- struct{}{}:
		default:
		}
		s.processJob(ctx, job)
	}
	return ctx.Err()
}

// sweepIfDue limits terminal-state sweeps to one per interval across all workers.
func (s *BulletinJobService) sweepIfDue(ctx context.Context) error {
	now := time.Now().UnixNano()
	last := s.lastSweep.Load()
	if now-last < int64(bulletinJobSweepInterval) || !s.lastSweep.CompareAndSwap(last, now) {
		return nil
	}
	if err := s.failExhausted(ctx); err != nil {
		// Let the next cycle retry immediately.
		s.lastSweep.Store(last)
		return err
	}
	return nil
}

func (s *BulletinJobService) failExhausted(ctx context.Context) error {
	exhausted, err := s.repo.FailExhausted(ctx, bulletinJobMaxAttempts,
		apperrors.CodeRetriesExhausted,
		"Bulletin generation was interrupted repeatedly and will not be retried")
	if err != nil {
		return err
	}
	stale, err := s.repo.FailStaleQueued(ctx, s.cfg.QueueTimeout,
		apperrors.CodeQueueTimeout,
		"The job was not picked up in time; retry the generation request")
	if err != nil {
		return err
	}
	if exhausted > 0 || stale > 0 {
		logger.Warn("Terminally failed exhausted bulletin jobs",
			"exhausted", exhausted, "stale_queued", stale)
	}
	return nil
}

func (s *BulletinJobService) processJob(workerCtx context.Context, job *models.BulletinJob) {
	bulletinID, err := s.generate(workerCtx, job)
	switch {
	case err == nil:
		logger.Info("Bulletin generation job completed", "job_id", job.ID, "bulletin_id", bulletinID)
	case workerCtx.Err() != nil:
		logger.Warn("Bulletin job interrupted during shutdown; requeueing",
			"job_id", job.ID, "attempt", job.Attempt, "error", err)
		s.releaseInterrupted(workerCtx, job)
	default:
		code, detail := bulletinJobError(err)
		logger.Error("Bulletin generation job failed", "job_id", job.ID, "station_id", job.StationID, "error", err)
		s.recordFailure(workerCtx, job, code, detail)
	}
}

// generate bounds one attempt and converts panics to errors for normal finalization.
func (s *BulletinJobService) generate(workerCtx context.Context, job *models.BulletinJob) (_ int64, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("bulletin generation panicked: %v", recovered)
		}
	}()

	jobCtx, cancel := context.WithTimeout(workerCtx, s.cfg.GenerationTimeout)
	defer cancel()
	return s.bulletins.create(jobCtx, job.StationID, job.TargetDate, func(
		txCtx context.Context,
		createdBulletinID int64,
	) error {
		return s.repo.Complete(txCtx, job.ID, job.Attempt, createdBulletinID)
	})
}

func (s *BulletinJobService) recordFailure(
	parent context.Context,
	job *models.BulletinJob,
	code string,
	detail string,
) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), bulletinJobUpdateTimeout)
	defer cancel()
	if err := s.repo.Fail(ctx, job.ID, job.Attempt, code, detail); err != nil {
		logger.Error("Failed to record bulletin job failure", "job_id", job.ID, "error", err)
	}
}

func (s *BulletinJobService) releaseInterrupted(parent context.Context, job *models.BulletinJob) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), bulletinJobUpdateTimeout)
	defer cancel()
	if err := s.repo.Release(ctx, job.ID, job.Attempt); err != nil {
		logger.Error("Failed to requeue interrupted bulletin job", "job_id", job.ID, "error", err)
	}
}

func bulletinJobError(err error) (code, detail string) {
	if _, ok := errors.AsType[*apperrors.NoStoriesError](err); ok {
		return apperrors.CodeBulletinNoStories, "No eligible stories are available for bulletin generation"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apperrors.CodeTimeout, "Bulletin generation exceeded the server-side time limit"
	}
	if _, ok := errors.AsType[*apperrors.AudioError](err); ok {
		return apperrors.CodeAudioProcessingFailed, "Audio processing failed during bulletin generation"
	}
	return apperrors.CodeGenerationFailed, jobDetailGenerationFailed
}
