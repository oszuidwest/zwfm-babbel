package database

import (
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestMySQLDSNClientFoundRows(t *testing.T) {
	if !strings.Contains(mysqlDSN(&config.Config{}), "clientFoundRows=true") {
		t.Fatal("DSN lacks clientFoundRows=true; same-second updates would report 0 rows")
	}
}

func TestMySQLDSNUsesUTCSession(t *testing.T) {
	cfg, err := mysql.ParseDSN(mysqlDSN(&config.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Loc != time.UTC {
		t.Errorf("loc = %v, want UTC", cfg.Loc)
	}
	if got := cfg.Params["time_zone"]; got != "'+00:00'" {
		t.Errorf("time_zone = %q, want '+00:00'", got)
	}
}

func TestMySQLDSNTransportTimeouts(t *testing.T) {
	t.Parallel()
	want := config.DatabaseConfig{ConnectTimeout: 3 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: time.Minute}
	got, err := mysql.ParseDSN(mysqlDSN(&config.Config{Database: want}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Timeout != want.ConnectTimeout || got.ReadTimeout != want.ReadTimeout || got.WriteTimeout != want.WriteTimeout {
		t.Fatalf("timeouts = %v/%v/%v, want %v/%v/%v", got.Timeout, got.ReadTimeout, got.WriteTimeout, want.ConnectTimeout, want.ReadTimeout, want.WriteTimeout)
	}
}
