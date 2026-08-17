package services

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	bulletinJobPollInterval   = time.Second
	bulletinJobUpdateTimeout  = 5 * time.Second
	defaultBulletinJobTimeout = 2 * time.Minute
)

// BulletinJobService queues, processes, and exposes durable generation jobs.
type BulletinJobService struct {
	repo       *repository.BulletinJobRepository
	bulletins  *BulletinService
	timeout    time.Duration
	leaseFor   time.Duration
	pollEvery  time.Duration
	wake       chan struct{}
	done       chan struct{}
	cancel     context.CancelFunc
	startOnce  sync.Once
	stopOnce   sync.Once
	startupErr error
}

// NewBulletinJobService creates an asynchronous bulletin worker.
func NewBulletinJobService(
	repo *repository.BulletinJobRepository,
	bulletins *BulletinService,
	timeout time.Duration,
) *BulletinJobService {
	if timeout <= 0 {
		timeout = defaultBulletinJobTimeout
	}
	return &BulletinJobService{
		repo:      repo,
		bulletins: bulletins,
		timeout:   timeout,
		leaseFor:  timeout + (2 * bulletinJobUpdateTimeout),
		pollEvery: bulletinJobPollInterval,
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
}

// Start starts the single bounded worker. Expired leases are reclaimed during
// normal claiming, so starting one replica never disturbs another replica.
func (s *BulletinJobService) Start(parent context.Context) error {
	s.startOnce.Do(func() {
		// #nosec G118 -- Stop retains and invokes cancel during graceful shutdown.
		workerCtx, cancel := context.WithCancel(parent)
		s.cancel = cancel
		go s.run(workerCtx)
	})
	return s.startupErr
}

// Stop cancels active generation and waits for the worker to exit.
func (s *BulletinJobService) Stop(ctx context.Context) error {
	if s.cancel == nil {
		return nil
	}
	s.stopOnce.Do(s.cancel)
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Enqueue persists a generation request before waking the worker.
func (s *BulletinJobService) Enqueue(
	ctx context.Context,
	stationID int64,
	targetDate time.Time,
) (*models.BulletinJob, error) {
	job, err := s.repo.Create(ctx, stationID, targetDate)
	if err != nil {
		return nil, apperrors.Database("Bulletin job", "create", err)
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
		return nil, apperrors.TranslateRepoError("Bulletin job", apperrors.OpQuery, err)
	}
	return job, nil
}

func (s *BulletinJobService) run(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(s.pollEvery)
	defer ticker.Stop()

	for {
		if err := s.processQueued(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("Bulletin job worker failed to claim work", "error", err)
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
	for ctx.Err() == nil {
		job, err := s.repo.ClaimNext(ctx, s.leaseFor)
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}
		s.processJob(ctx, job)
	}
	return ctx.Err()
}

func (s *BulletinJobService) processJob(workerCtx context.Context, job *models.BulletinJob) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("Bulletin generation job panicked", "job_id", job.ID, "panic", recovered)
			if workerCtx.Err() != nil {
				s.releaseInterrupted(workerCtx, job)
				return
			}
			s.recordFailure(workerCtx, job, "internal.generation_failed", "Bulletin generation failed")
		}
	}()

	jobCtx, cancel := context.WithTimeout(workerCtx, s.timeout)
	bulletinID, err := s.bulletins.create(jobCtx, job.StationID, job.TargetDate, func(
		txCtx context.Context,
		createdBulletinID int64,
	) error {
		return s.repo.Complete(txCtx, job.ID, job.Attempt, createdBulletinID)
	})
	cancel()
	if err != nil {
		if workerCtx.Err() != nil {
			s.releaseInterrupted(workerCtx, job)
			return
		}
		code, detail := bulletinJobError(err)
		logger.Error("Bulletin generation job failed", "job_id", job.ID, "station_id", job.StationID, "error", err)
		s.recordFailure(workerCtx, job, code, detail)
		return
	}
	logger.Info("Bulletin generation job completed", "job_id", job.ID, "bulletin_id", bulletinID)
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
		return "bulletin.no_stories", "No eligible stories are available for bulletin generation"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "internal.timeout", "Bulletin generation exceeded the server-side time limit"
	}
	return "internal.generation_failed", "Bulletin generation failed"
}
