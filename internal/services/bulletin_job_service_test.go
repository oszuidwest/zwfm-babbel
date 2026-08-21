package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
)

func newTestJobService(t *testing.T) *BulletinJobService {
	t.Helper()
	return NewBulletinJobService(nil, NewBulletinService(BulletinServiceDeps{}), config.BulletinJobConfig{
		GenerationTimeout: time.Second,
		QueueTimeout:      time.Minute,
		Workers:           1,
	}, nil)
}

func TestResolveJobOutcome(t *testing.T) {
	t.Parallel()

	shutdown, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want jobResolution
	}{
		{
			name: "success",
			ctx:  context.Background(),
			err:  nil,
			want: jobSucceeded,
		},
		{
			name: "lease lost through the transaction wrapper",
			ctx:  context.Background(),
			err:  apperrors.Database("Bulletin", "create", repository.ErrBulletinJobLeaseLost),
			want: jobLeaseLost,
		},
		{
			name: "no stories stays terminal during shutdown",
			ctx:  shutdown,
			err:  apperrors.NoStories(4),
			want: jobFailed,
		},
		{
			// The audio layer joins ctx errors into runs killed by cancellation.
			name: "killed generation requeues during shutdown",
			ctx:  shutdown,
			err: apperrors.Audio("Bulletin", "generate",
				fmt.Errorf("ffmpeg bulletin failed: %w", errors.Join(context.Canceled, errors.New("signal: killed")))),
			want: jobInterrupted,
		},
		{
			name: "cancelled lock wait requeues during shutdown",
			ctx:  shutdown,
			err:  context.Canceled,
			want: jobInterrupted,
		},
		{
			name: "database failure during shutdown requeues",
			ctx:  shutdown,
			err:  apperrors.Database("Bulletin", "create", errors.New("invalid connection")),
			want: jobInterrupted,
		},
		{
			name: "real audio failure stays terminal during shutdown",
			ctx:  shutdown,
			err:  apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg exit status 1")),
			want: jobFailed,
		},
		{
			name: "elapsed generation budget stays terminal during shutdown",
			ctx:  shutdown,
			err:  apperrors.Audio("Bulletin", "generate", errors.Join(context.DeadlineExceeded, errors.New("signal: killed"))),
			want: jobFailed,
		},
		{
			name: "panic stays terminal during shutdown",
			ctx:  shutdown,
			err:  fmt.Errorf("%w: nil map write", errGenerationPanic),
			want: jobFailed,
		},
		{
			name: "audio failure without shutdown is terminal",
			ctx:  context.Background(),
			err:  apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg exit status 1")),
			want: jobFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveJobOutcome(test.ctx, test.err); got != test.want {
				t.Fatalf("resolveJobOutcome() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestGenerateConvertsPanicToError(t *testing.T) {
	t.Parallel()

	svc := newTestJobService(t)
	svc.generateBulletin = func(context.Context, int64, time.Time, func(context.Context, int64) error) (int64, error) {
		panic("renderer exploded")
	}

	_, err := svc.generate(context.Background(), &models.BulletinJob{ID: 1, StationID: 2})
	if !errors.Is(err, errGenerationPanic) {
		t.Fatalf("generate() error = %v, want panic converted to errGenerationPanic", err)
	}
	if got := resolveJobOutcome(context.Background(), err); got != jobFailed {
		t.Fatalf("resolveJobOutcome() = %d, want jobFailed for a panic", got)
	}
}

func TestRunAttemptStopsWaitingForStationLockOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := newTestJobService(t)
		release, err := svc.bulletins.LockStation(context.Background(), 7)
		if err != nil {
			t.Fatalf("LockStation() error = %v", err)
		}
		defer release()
		svc.generateBulletin = func(context.Context, int64, time.Time, func(context.Context, int64) error) (int64, error) {
			t.Fatal("generation must not run without the station lock")
			return 0, nil
		}

		// Virtual time only advances once runAttempt is durably blocked in its
		// wait slice, so the cancel provably interrupts an in-progress wait.
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Millisecond)
			cancel()
		}()
		defer cancel()
		_, err = svc.runAttempt(ctx, &models.BulletinJob{ID: 1, StationID: 7})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runAttempt() error = %v, want context.Canceled", err)
		}
		if got := resolveJobOutcome(ctx, err); got != jobInterrupted {
			t.Fatalf("resolveJobOutcome() = %d, want jobInterrupted for a cancelled lock wait", got)
		}
	})
}

func TestRunAttemptExtendsLeaseWhileWaitingForStationLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		svc := newTestJobService(t)
		var extensions, generations int
		svc.extendLease = func(_ context.Context, id int64, attempt int, _ time.Duration) error {
			if id != 1 || attempt != 2 {
				t.Errorf("extendLease(id=%d, attempt=%d), want job 1 attempt 2", id, attempt)
			}
			extensions++
			return nil
		}
		svc.generateBulletin = func(context.Context, int64, time.Time, func(context.Context, int64) error) (int64, error) {
			generations++
			return 42, nil
		}

		release, err := svc.bulletins.LockStation(context.Background(), 7)
		if err != nil {
			t.Fatalf("LockStation() error = %v", err)
		}
		go func() {
			// Free the lock just after one wait slice elapses, so exactly one
			// in-wait heartbeat must fire before acquisition.
			time.Sleep(svc.leaseFor()/2 + time.Millisecond)
			release()
		}()

		bulletinID, err := svc.runAttempt(context.Background(), &models.BulletinJob{ID: 1, StationID: 7, Attempt: 2})
		if err != nil || bulletinID != 42 {
			t.Fatalf("runAttempt() = %d, %v; want 42, nil", bulletinID, err)
		}
		// One heartbeat during the wait plus the final re-arm after acquisition.
		if extensions != 2 {
			t.Fatalf("lease extensions = %d, want 2", extensions)
		}
		if generations != 1 {
			t.Fatalf("generations = %d, want exactly 1", generations)
		}
	})
}

func TestBulletinJobError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantCode   string
		wantDetail string
	}{
		{
			name:       "no stories",
			err:        apperrors.NoStories(12),
			wantCode:   "bulletin.no_stories",
			wantDetail: "No eligible stories are available for bulletin generation",
		},
		{
			name:       "timeout",
			err:        context.DeadlineExceeded,
			wantCode:   "internal.timeout",
			wantDetail: "Bulletin generation exceeded the server-side time limit",
		},
		{
			name:       "audio failure",
			err:        apperrors.Audio("Bulletin", "generate", errors.New("ffmpeg exit status 1")),
			wantCode:   "audio.processing_failed",
			wantDetail: "Audio processing failed during bulletin generation",
		},
		{
			name:       "internal error",
			err:        errors.New("sensitive renderer failure"),
			wantCode:   "internal.generation_failed",
			wantDetail: "Bulletin generation failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			code, detail := bulletinJobError(test.err)
			if code != test.wantCode || detail != test.wantDetail {
				t.Fatalf("bulletinJobError() = %q, %q; want %q, %q", code, detail, test.wantCode, test.wantDetail)
			}
		})
	}
}
