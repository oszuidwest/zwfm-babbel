//go:build integration

package database

import (
	"net"
	"strconv"
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

// openAppDB opens the integration database through NewGormDB, so the test
// uses the application's DSN rather than BABBEL_TEST_DB_DSN's options.
func openAppDB(t *testing.T) *gorm.DB {
	t.Helper()
	parsed, err := mysql.ParseDSN(testutil.IntegrationDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(parsed.Addr)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	db, err := NewGormDB(&config.Config{Database: config.DatabaseConfig{
		Host: host, Port: portNumber, User: parsed.User, Password: parsed.Passwd, Database: parsed.DBName,
		MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute,
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
