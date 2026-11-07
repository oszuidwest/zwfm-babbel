//go:build integration

package database

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

// In Europe/Amsterdam both instants have the local time 02:30, so a session
// that sends local wall-clock time cannot keep them apart. CI runs with that TZ.
func TestNewGormDBKeepsTimestampsInTheRepeatedHour(t *testing.T) {
	db := openAppDB(t)
	want := []time.Time{
		time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC),
		time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC),
	}
	var sessionZone string
	var got []struct {
		At    time.Time
		Epoch int64
	}
	// A temporary table lives on one connection.
	err := db.Connection(func(tx *gorm.DB) error {
		if err := tx.Raw("SELECT @@session.time_zone").Scan(&sessionZone).Error; err != nil {
			return err
		}
		if err := tx.Exec("CREATE TEMPORARY TABLE repeated_hour (id INT PRIMARY KEY, at TIMESTAMP NULL)").Error; err != nil {
			return err
		}
		for i, at := range want {
			if err := tx.Exec("INSERT INTO repeated_hour (id, at) VALUES (?, ?)", i, at).Error; err != nil {
				return err
			}
		}
		return tx.Raw("SELECT at, UNIX_TIMESTAMP(at) AS epoch FROM repeated_hour ORDER BY id").Scan(&got).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	if sessionZone != "+00:00" {
		t.Errorf("session time_zone = %q, want +00:00", sessionZone)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d rows, want %d", len(got), len(want))
	}
	// The epoch checks storage; the read checks the decoded value.
	for i := range want {
		if got[i].Epoch != want[i].Unix() || !got[i].At.Equal(want[i]) {
			t.Errorf("row %d = %s (epoch %d), want %s (epoch %d)", i,
				got[i].At.UTC().Format(time.RFC3339), got[i].Epoch, want[i].Format(time.RFC3339), want[i].Unix())
		}
	}
}

// This reloads 001, as make db-reset does. The server default must not decide
// which text a table takes: on latin1, a column rejects IPA, ğ and emoji.
func TestSnapshotIsUTF8MB4OnALatin1Database(t *testing.T) {
	cfg, err := mysql.ParseDSN(testutil.IntegrationDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MultiStatements = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	snapshot, err := os.ReadFile("../../migrations/001_complete_schema.sql")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(t.Context(), "ALTER DATABASE CHARACTER SET latin1 COLLATE latin1_swedish_ci"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), string(snapshot)); err != nil {
		t.Fatal(err)
	}

	rows, err := db.QueryContext(t.Context(), `SELECT CONCAT(TABLE_NAME, '.', COLUMN_NAME) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND CHARACTER_SET_NAME <> 'utf8mb4'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		t.Errorf("column %s is not utf8mb4", column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// openAppDB opens the integration database through NewGormDB, so the test
// uses the application's DSN rather than BABBEL_TEST_DB_DSN's options.
func openAppDB(t *testing.T) *gorm.DB {
	t.Helper()
	parsed, err := mysql.ParseDSN(testutil.IntegrationDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewGormDB(&config.Config{Database: config.DatabaseConfig{
		Host: parsed.Addr, User: parsed.User, Password: parsed.Passwd, Database: parsed.DBName,
		MaxOpenConns: 1, ConnMaxLifetime: time.Minute,
		ConnectTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
	}})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}
