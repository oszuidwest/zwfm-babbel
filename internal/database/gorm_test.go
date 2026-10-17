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
