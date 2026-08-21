package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	namedLockReleaseTimeout = 5 * time.Second

	// Enqueue locks protect one lookup and insert.
	enqueueLockWait = 5 * time.Second

	// Bound callers that omit a deadline.
	generationLockFallbackWait = time.Minute
)

// NamedLockManager acquires connection-bound MySQL locks.
type NamedLockManager struct {
	db *sql.DB
}

// NewNamedLockManager uses db as its dedicated lock pool.
func NewNamedLockManager(db *sql.DB) *NamedLockManager {
	return &NamedLockManager{db: db}
}

// LockStationGeneration serializes station generation across replicas. It waits
// until the context deadline, or up to one minute when none is set. The returned
// function releases the lock.
func (m *NamedLockManager) LockStationGeneration(ctx context.Context, stationID int64) (func(), error) {
	wait := generationLockFallbackWait
	if deadline, ok := ctx.Deadline(); ok {
		wait = time.Until(deadline)
	}
	if wait <= 0 {
		return nil, context.DeadlineExceeded
	}
	return m.acquire(ctx, fmt.Sprintf("babbel:bulletin:generate:station:%d", stationID), wait)
}

// LockEnqueue serializes a station's find-create pair across replicas. The
// returned function releases the lock.
func (m *NamedLockManager) LockEnqueue(ctx context.Context, stationID int64) (func(), error) {
	return m.acquire(ctx, fmt.Sprintf("babbel:bulletin-jobs:enqueue:station:%d", stationID), enqueueLockWait)
}

func (m *NamedLockManager) acquire(ctx context.Context, name string, wait time.Duration) (func(), error) {
	// One timeout covers pool acquisition and GET_LOCK; the held connection outlives it.
	lockCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	conn, err := m.db.Conn(lockCtx)
	if err != nil {
		return nil, fmt.Errorf("named lock %q not acquired within %s: %w", name, wait, err)
	}

	var acquired sql.NullInt64
	seconds := int(math.Ceil(wait.Seconds()))
	if err := conn.QueryRowContext(lockCtx, "SELECT GET_LOCK(?, ?)", name, seconds).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !acquired.Valid || acquired.Int64 != 1 {
		_ = conn.Close()
		return nil, fmt.Errorf("named lock %q not acquired within %s: %w", name, wait, context.DeadlineExceeded)
	}

	release := func() {
		// Discard the session unless release is confirmed.
		releaseCtx, cancel := context.WithTimeout(context.Background(), namedLockReleaseTimeout)
		defer cancel()

		var released sql.NullInt64
		err := conn.QueryRowContext(releaseCtx, "SELECT RELEASE_LOCK(?)", name).Scan(&released)
		if err != nil || !released.Valid || released.Int64 != 1 {
			if err != nil {
				logger.Error("Failed to release named lock", "lock", name, "error", err)
			} else {
				logger.Error("Named lock release was not confirmed", "lock", name,
					"result", released.Int64, "valid", released.Valid)
			}
			if discardErr := conn.Raw(func(any) error { return driver.ErrBadConn }); discardErr != nil &&
				!errors.Is(discardErr, driver.ErrBadConn) &&
				!errors.Is(discardErr, sql.ErrConnDone) {
				logger.Error("Failed to discard named lock connection", "lock", name, "error", discardErr)
			}
		}
		if err := conn.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			logger.Error("Failed to close named lock connection", "lock", name, "error", err)
		}
	}
	return release, nil
}
