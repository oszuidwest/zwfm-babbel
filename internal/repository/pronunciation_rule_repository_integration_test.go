//go:build integration

package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestPronunciationRuleRepositoryIntegration_FalseFlagsRoundTrip(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	err := txManager.WithTransaction(t.Context(), func(ctx context.Context) error {
		if err := repo.LockSingletonForWrite(ctx); err != nil {
			return err
		}
		return repo.ReplaceAll(ctx, []models.PronunciationRule{{
			StringToReplace: "PSV",
			IPA:             "piː ɛs veː",
			CaseSensitive:   false,
			WordBoundaries:  false,
		}})
	})
	if err != nil {
		t.Fatalf("replace rules: %v", err)
	}

	rules, err := repo.List(t.Context())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(rules))
	}
	if rules[0].CaseSensitive || rules[0].WordBoundaries {
		t.Fatalf("flags = %t/%t, want false/false", rules[0].CaseSensitive, rules[0].WordBoundaries)
	}
}

func TestPronunciationRuleRepositoryIntegration_CaseSensitiveUniqueIndex(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	err := txManager.WithTransaction(t.Context(), func(ctx context.Context) error {
		if err := repo.LockSingletonForWrite(ctx); err != nil {
			return err
		}
		return repo.ReplaceAll(ctx, []models.PronunciationRule{
			{StringToReplace: "PSV", IPA: "one", CaseSensitive: true, WordBoundaries: true},
			{StringToReplace: "psv", IPA: "two", CaseSensitive: true, WordBoundaries: true},
		})
	})
	if err != nil {
		t.Fatalf("ReplaceAll() error = %v, want nil for case-distinct terms", err)
	}
}

func TestPronunciationRuleRepositoryIntegration_MaxUpdatedAtEmpty(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	err := txManager.WithTransaction(t.Context(), func(ctx context.Context) error {
		if err := repo.LockSingletonForWrite(ctx); err != nil {
			return err
		}
		return repo.ReplaceAll(ctx, nil)
	})
	if err != nil {
		t.Fatalf("clear rules: %v", err)
	}

	updatedAt, err := repo.MaxUpdatedAt(t.Context())
	if err != nil {
		t.Fatalf("MaxUpdatedAt() error = %v", err)
	}
	if updatedAt != nil {
		t.Fatalf("updatedAt = %v, want nil", updatedAt)
	}
}

func TestPronunciationRuleRepositoryIntegration_LockSingletonForWriteBlocksConcurrentWriters(t *testing.T) {
	db := openIntegrationDB(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	sqlDB.SetMaxOpenConns(5)
	sqlDB.SetMaxIdleConns(5)

	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	parent, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tx1Locked := make(chan struct{})
	tx1Err := make(chan error, 1)
	release := make(chan struct{})

	go func() {
		tx1Err <- txManager.WithTransaction(parent, func(ctx context.Context) error {
			if err := repo.LockSingletonForWrite(ctx); err != nil {
				return err
			}
			close(tx1Locked)
			<-release
			return nil
		})
	}()

	select {
	case <-tx1Locked:
	case err := <-tx1Err:
		t.Fatalf("tx1 failed before lock: %v", err)
	case <-parent.Done():
		t.Fatalf("tx1 did not acquire lock: %v", parent.Err())
	}

	tx2Started := make(chan struct{})
	tx2Done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		defer cancel()
		tx2Done <- txManager.WithTransaction(ctx, func(ctx context.Context) error {
			close(tx2Started)
			return repo.LockSingletonForWrite(ctx)
		})
	}()

	select {
	case <-tx2Started:
	case <-parent.Done():
		t.Fatalf("tx2 did not start lock attempt: %v", parent.Err())
	}

	select {
	case err := <-tx2Done:
		t.Fatalf("tx2 lock returned before tx1 commit: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-tx2Done:
		if err != nil {
			t.Fatalf("tx2 lock after release error = %v", err)
		}
	case <-parent.Done():
		t.Fatalf("tx2 did not acquire lock after release: %v", parent.Err())
	}

	select {
	case err := <-tx1Err:
		if err != nil {
			t.Fatalf("tx1 error = %v", err)
		}
	default:
	}
}

func openIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}

	db, err := gorm.Open(
		gormmysql.Open(dsn),
		&gorm.Config{SkipDefaultTransaction: true},
	)
	if err != nil {
		t.Fatalf("gorm.Open(): %v", err)
	}
	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatalf("db.DB(): %v", err)
		}
		if err := sqlDB.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("close db: %v", err)
		}
	})
	return db
}
