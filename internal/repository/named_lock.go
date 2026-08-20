package repository

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	namedLockReleaseTimeout = 5 * time.Second

	// enqueueLockWait bounds how long an enqueue waits on a concurrent enqueue
	// for the same station; the critical section is one lookup and one insert,
	// so real contention resolves in milliseconds.
	enqueueLockWait = 5 * time.Second

	// generationLockFallbackWait bounds the generation lock wait when the
	// caller's context carries no deadline; both production paths (job worker
	// and automation endpoint) pass generation-timeout contexts, so this only
	// guards misuse.
	generationLockFallbackWait = time.Minute
)

// NamedLockManager acquires MySQL named locks (GET_LOCK) on a dedicated
// connection pool. Named locks pin their connection while held, so they must
// never draw from the regular query pool: the queries a lock protects would
// then compete with the lock itself for connections, which deadlocks outright
// when BABBEL_DB_MAX_OPEN_CONNS is exhausted by lock holders.
type NamedLockManager struct {
	db *sql.DB
}

// NewNamedLockManager creates a lock manager on the dedicated lock pool from
// database.NewLockDB.
func NewNamedLockManager(db *sql.DB) *NamedLockManager {
	return &NamedLockManager{db: db}
}

// LockStationGeneration takes the cross-replica generation lock for a station,
// so two processes can never run story selection and fair-rotation updates for
// the same station concurrently. Waiting is bounded by the context deadline;
// the returned release function must be called when generation completes.
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

// LockEnqueue serializes enqueues for a station across all replicas, making
// the find-then-create pair in BulletinJobService.Enqueue atomic so concurrent
// requests coalesce instead of racing into duplicate jobs. The returned
// release function must be called when the enqueue completes.
func (m *NamedLockManager) LockEnqueue(ctx context.Context, stationID int64) (func(), error) {
	return m.acquire(ctx, fmt.Sprintf("babbel:bulletin-jobs:enqueue:station:%d", stationID), enqueueLockWait)
}

// acquire takes a MySQL named lock and returns a release function. The lock is
// held on a dedicated pooled connection that stays pinned until release; if
// the process or connection dies, MySQL releases the lock server-side. Waiting
// is bounded by wait and by ctx cancellation.
func (m *NamedLockManager) acquire(ctx context.Context, name string, wait time.Duration) (func(), error) {
	// wait bounds the whole acquisition: waiting for a free pool connection
	// first, then the server-side GET_LOCK wait. Without the combined budget,
	// a lock pool exhausted by long-held generation locks would stall
	// acquirers far beyond their advertised timeout. The context only governs
	// acquisition, so canceling it on return does not affect the held
	// connection.
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
		// The lock must be dropped before the connection returns to the pool;
		// on a broken connection the server has already released it.
		releaseCtx, cancel := context.WithTimeout(context.Background(), namedLockReleaseTimeout)
		defer cancel()
		if _, err := conn.ExecContext(releaseCtx, "DO RELEASE_LOCK(?)", name); err != nil {
			logger.Error("Failed to release named lock", "lock", name, "error", err)
		}
		if err := conn.Close(); err != nil {
			logger.Error("Failed to close named lock connection", "lock", name, "error", err)
		}
	}
	return release, nil
}
