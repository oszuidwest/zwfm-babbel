package database

import (
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestMySQLDSNClientFoundRows(t *testing.T) {
	if !strings.Contains(mysqlDSN(&config.Config{}), "clientFoundRows=true") {
		t.Fatal("DSN lacks clientFoundRows=true; same-second updates would report 0 rows")
	}
}
