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

// integrationDSN returns the shared integration database DSN, failing in CI
// and skipping locally when it is not configured.
func integrationDSN(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}
	return dsn
}

// OpenIntegrationDB opens the integration database and closes it on cleanup.
func OpenIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(gormmysql.Open(integrationDSN(t)), &gorm.Config{SkipDefaultTransaction: true})
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
