//go:build integration

// Package testutil holds helpers shared by integration tests.
package testutil

import (
	"context"
	"errors"
	"os"
	"testing"

	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// OpenIntegrationDB opens the database named by BABBEL_TEST_DB_DSN and closes
// it on cleanup. Without a DSN it fails in CI and skips locally.
func OpenIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()

	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}

	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{SkipDefaultTransaction: true})
	if err != nil {
		t.Fatalf("gorm.Open(): %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("close db: %v", err)
		}
	})
	return db
}
