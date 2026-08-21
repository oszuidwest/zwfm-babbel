package services

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	// Poll for missed wakes; Enqueue wakes the worker directly.
	bulletinJobPollInterval  = 5 * time.Second
	bulletinJobUpdateTimeout = 5 * time.Second

	// Bound crash-restart retries so one poison job cannot crash-loop the
	// process indefinitely.
	bulletinJobMaxAttempts = 3

	jobDetailGenerationFailed = "Bulletin generation failed"
	jobDetailRetriesExhausted = "Bulletin generation was interrupted repeatedly and will not be retried"

	claimAlertKey = "bulletin-jobs:claim"
)

// BulletinJobService queues, processes, and exposes durable generation jobs.
// A single worker processes jobs one at a time; the process boundary is the
// only failure domain, so crash recovery is a startup requeue rather than
// lease bookkeeping.
type BulletinJobService struct {
	repo      *repository.BulletinJobRepository
	bulletins *BulletinService
	alerts    notify.Alerter
	cfg       config.BulletinJobConfig
	wake      chan struct{}
	done      chan struct{}
	cancel    context.CancelFunc
	startOnce sync.Once

	// recovered is touched only by the worker goroutine.
	recovered bool

	// generateBulletin produces one bulletin; tests replace it to inject failures.
	generateBulletin func(ctx context.Context, stationID int64, targetDate time.Time,
		finalize func(context.Context, int64) error) (int64, error)
}

// NewBulletinJobService returns a stopped worker; cfg must be validated.
func NewBulletinJobService(
	repo *repository.BulletinJobRepository,
	bulletins *BulletinService,
	cfg config.BulletinJobConfig,
	alerts notify.Alerter,
) *BulletinJobService {
	return &BulletinJobService{
		repo:             repo,
		bulletins:        bulletins,
		alerts:           notify.OrDiscard(alerts),
		cfg:              cfg,
		wake:             make(chan struct{}, 1),
		done:             make(chan struct{}),
		generateBulletin: bulletins.create,
	}
}

// Start launches the worker goroutine.
func (s *BulletinJobService) Start() {
	s.startOnce.Do(func() {
		workerCtx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		go func() {
			defer close(s.done)
			s.run(workerCtx)
		}()
	})
}

// Stop cancels active generation and waits for the worker to exit.
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

// Enqueue persists a generation request and wakes the worker.
func (s *BulletinJobService) Enqueue(
	ctx context.Context,
	stationID int64,
	targetDate time.Time,
) (*models.BulletinJob, error) {
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
			logger.Error("Bulletin job worker cycle failed", "error", err)
			s.alerts.Alert(ctx, notify.Event{
				Key:               claimAlertKey,
				Summary:           "Bulletin job worker cannot process jobs",
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

func (s *BulletinJobService) processQueued(ctx context.Context) (err error) {
	// A failed cycle may have left a job running in the database, e.g. a
	// claim or finalization whose commit landed but whose response was lost.
	// Rearm recovery so the next cycle requeues such jobs.
	defer func() {
		if err != nil {
			s.recovered = false
		}
	}()

	if err := s.recoverOnce(ctx); err != nil {
		return err
	}
	for ctx.Err() == nil {
		job, err := s.repo.ClaimNext(ctx, bulletinJobMaxAttempts)
		if err != nil {
			return err
		}
		if job == nil {
			return nil
		}
		if err := s.processJob(ctx, job); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// recoverOnce requeues jobs left running by an unclean shutdown or a failed
// finalization, and terminally fails jobs whose attempt budget is spent. It
// runs before the first claim and again after any finalization failure; the
// single worker never has a live attempt while it runs.
func (s *BulletinJobService) recoverOnce(ctx context.Context) error {
	if s.recovered {
		return nil
	}
	requeued, err := s.repo.RequeueInterrupted(ctx)
	if err != nil {
		return err
	}
	exhausted, err := s.repo.FailExhausted(ctx, bulletinJobMaxAttempts,
		apperrors.CodeRetriesExhausted, jobDetailRetriesExhausted)
	if err != nil {
		return err
	}
	if requeued > 0 || exhausted > 0 {
		logger.Warn("Recovered interrupted bulletin jobs",
			"requeued", requeued, "exhausted", exhausted)
	}
	s.recovered = true
	return nil
}

// jobResolution classifies a finished generation attempt.
type jobResolution int

const (
	jobSucceeded jobResolution = iota
	jobConflict
	jobInterrupted
	jobFailed
)

// errGenerationPanic marks attempts that panicked; panics are never
// cancellation, so they finalize as failures even during shutdown.
var errGenerationPanic = errors.New("bulletin generation panicked")

// resolveJobOutcome decides how to finalize an attempt. Deterministic failures
// (no stories, panics, an elapsed generation budget, real audio errors) stay
// terminal even when shutdown starts concurrently; cancellations requeue. The
// audio layer joins ctx errors into killed FFmpeg runs, but database drivers
// can surface cancellation as unrelated connection errors, so the worker
// context remains the final interruption check for the remaining paths.
func resolveJobOutcome(workerCtx context.Context, err error) jobResolution {
	switch {
	case err == nil:
		return jobSucceeded
	case errors.Is(err, repository.ErrBulletinJobStateConflict):
		return jobConflict
	case isNoStories(err), errors.Is(err, errGenerationPanic):
		return jobFailed
	case errors.Is(err, context.DeadlineExceeded):
		// The attempt genuinely used its generation budget.
		return jobFailed
	case errors.Is(err, context.Canceled):
		return jobInterrupted
	case isAudioFailure(err):
		return jobFailed
	case workerCtx.Err() != nil:
		return jobInterrupted
	default:
		return jobFailed
	}
}

func isNoStories(err error) bool {
	_, ok := errors.AsType[*apperrors.NoStoriesError](err)
	return ok
}

func isAudioFailure(err error) bool {
	_, ok := errors.AsType[*apperrors.AudioError](err)
	return ok
}

// processJob runs one attempt and finalizes its outcome. A non-nil return
// means the finalization itself failed and the job may still be running in
// the database; the caller rearms recovery to requeue it.
func (s *BulletinJobService) processJob(workerCtx context.Context, job *models.BulletinJob) error {
	bulletinID, err := s.runAttempt(workerCtx, job)
	switch resolveJobOutcome(workerCtx, err) {
	case jobSucceeded:
		logger.Info("Bulletin generation job completed", "job_id", job.ID, "bulletin_id", bulletinID)
		return nil
	case jobConflict:
		// The job is no longer in the state this attempt expected, e.g. a
		// Complete commit landed but its response was lost. The stored state
		// stays authoritative; overwriting it could corrupt a terminal job.
		logger.Warn("Bulletin job update conflicted with stored state; leaving the job as-is",
			"job_id", job.ID, "attempt", job.Attempt, "error", err)
		return nil
	case jobInterrupted:
		if job.Attempt >= bulletinJobMaxAttempts {
			logger.Error("Bulletin job interrupted on its final attempt; failing terminally",
				"job_id", job.ID, "attempt", job.Attempt, "error", err)
			return s.recordFailure(workerCtx, job, apperrors.CodeRetriesExhausted, jobDetailRetriesExhausted)
		}
		logger.Warn("Bulletin job interrupted during shutdown; requeueing",
			"job_id", job.ID, "attempt", job.Attempt, "error", err)
		return s.releaseInterrupted(workerCtx, job)
	default:
		code, detail := bulletinJobError(err)
		logger.Error("Bulletin generation job failed", "job_id", job.ID, "station_id", job.StationID, "error", err)
		return s.recordFailure(workerCtx, job, code, detail)
	}
}

// runAttempt serializes one attempt behind the station lock shared with the
// synchronous automation path. The generation timeout starts after the lock,
// so time spent waiting behind another generation does not consume it.
func (s *BulletinJobService) runAttempt(workerCtx context.Context, job *models.BulletinJob) (int64, error) {
	release, err := s.bulletins.LockStation(workerCtx, job.StationID)
	if err != nil {
		return 0, err
	}
	defer release()

	return s.generate(workerCtx, job)
}

// generate bounds one attempt and converts panics to errors for normal finalization.
func (s *BulletinJobService) generate(workerCtx context.Context, job *models.BulletinJob) (_ int64, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %v", errGenerationPanic, recovered)
		}
	}()

	jobCtx, cancel := context.WithTimeout(workerCtx, s.cfg.GenerationTimeout)
	defer cancel()
	return s.generateBulletin(jobCtx, job.StationID, job.TargetDate, func(
		txCtx context.Context,
		createdBulletinID int64,
	) error {
		return s.repo.Complete(txCtx, job.ID, createdBulletinID)
	})
}

func (s *BulletinJobService) recordFailure(
	parent context.Context,
	job *models.BulletinJob,
	code string,
	detail string,
) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), bulletinJobUpdateTimeout)
	defer cancel()
	return checkedFinalization(s.repo.Fail(ctx, job.ID, code, detail), job)
}

func (s *BulletinJobService) releaseInterrupted(parent context.Context, job *models.BulletinJob) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), bulletinJobUpdateTimeout)
	defer cancel()
	return checkedFinalization(s.repo.Release(ctx, job.ID), job)
}

// checkedFinalization swallows state conflicts: the job already reached
// another state, which stays authoritative. Any other error means the job may
// still be running in the database and must reach the caller.
func checkedFinalization(err error, job *models.BulletinJob) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, repository.ErrBulletinJobStateConflict) {
		logger.Warn("Bulletin job finalization conflicted with stored state; leaving the job as-is",
			"job_id", job.ID, "attempt", job.Attempt)
		return nil
	}
	return fmt.Errorf("finalize bulletin job %d: %w", job.ID, err)
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
