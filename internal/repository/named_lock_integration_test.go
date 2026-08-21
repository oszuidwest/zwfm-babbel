//go:build integration

package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

func openIntegrationLockDB(t *testing.T) *sql.DB {
	t.Helper()

	lockDB, err := sql.Open("mysql", integrationTestDSN(t))
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	t.Cleanup(func() {
		if err := lockDB.Close(); err != nil {
			t.Errorf("close lock db: %v", err)
		}
	})
	return lockDB
}

func TestNamedLockIntegration_MutualExclusion(t *testing.T) {
	locks := NewNamedLockManager(openIntegrationLockDB(t))
	name := fmt.Sprintf("babbel:test:%d", time.Now().UnixNano())

	release, err := locks.acquire(t.Context(), name, time.Second)
	if err != nil {
		t.Fatalf("first acquire() error = %v", err)
	}

	if _, err := locks.acquire(t.Context(), name, time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquire() error = %v, want DeadlineExceeded while lock is held", err)
	}

	release()
	again, err := locks.acquire(t.Context(), name, time.Second)
	if err != nil {
		t.Fatalf("acquire() after release error = %v", err)
	}
	again()
}

func TestNamedLockIntegration_StationGenerationLockRespectsDeadline(t *testing.T) {
	locks := NewNamedLockManager(openIntegrationLockDB(t))

	release, err := locks.LockStationGeneration(t.Context(), 424242)
	if err != nil {
		t.Fatalf("LockStationGeneration() error = %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := locks.LockStationGeneration(ctx, 424242); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second LockStationGeneration() error = %v, want DeadlineExceeded", err)
	}
}

func TestNamedLockIntegration_WaitBoundsPoolAcquisition(t *testing.T) {
	lockDB := openIntegrationLockDB(t)
	lockDB.SetMaxOpenConns(1)
	locks := NewNamedLockManager(lockDB)

	base := time.Now().UnixNano()
	release, err := locks.acquire(t.Context(), fmt.Sprintf("babbel:test:%d:a", base), time.Second)
	if err != nil {
		t.Fatalf("first acquire() error = %v", err)
	}

	// Use another name so only pool exhaustion can block acquisition.
	start := time.Now()
	_, err = locks.acquire(t.Context(), fmt.Sprintf("babbel:test:%d:b", base), 300*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second acquire() error = %v, want DeadlineExceeded from the pool wait", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("second acquire() took %s, want it to give up around its 300ms wait", elapsed)
	}

	release()
	again, err := locks.acquire(t.Context(), fmt.Sprintf("babbel:test:%d:b", base), time.Second)
	if err != nil {
		t.Fatalf("acquire() after release error = %v", err)
	}
	again()
}

func TestNamedLockIntegration_HeldLockDoesNotStarveQueryPool(t *testing.T) {
	db := openIntegrationDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	sqlDB.SetMaxOpenConns(1)

	locks := NewNamedLockManager(openIntegrationLockDB(t))
	release, err := locks.LockEnqueue(t.Context(), 424242)
	if err != nil {
		t.Fatalf("LockEnqueue() error = %v", err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var one int
	if err := db.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error; err != nil || one != 1 {
		t.Fatalf("query while lock held = %d, %v; want 1, nil", one, err)
	}
}
