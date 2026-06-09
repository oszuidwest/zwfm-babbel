//go:build integration

package repository

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/models"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestPronunciationRuleRepositoryIntegration_FalseFlagsRoundTrip(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	err := txManager.WithTransaction(t.Context(), func(ctx context.Context) error {
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

func TestPronunciationRuleRepositoryIntegration_CaseSensitivePrimaryKey(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	txManager := NewTxManager(db)

	err := txManager.WithTransaction(t.Context(), func(ctx context.Context) error {
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
