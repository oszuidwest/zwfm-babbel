package database

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestMySQLDSNClientFoundRows(t *testing.T) {
	t.Parallel()

	dsn, err := mysql.ParseDSN(mysqlDSN(&config.Config{}))
	if err != nil {
		t.Fatalf("ParseDSN(): %v", err)
	}
	if !dsn.ClientFoundRows {
		t.Fatal("ClientFoundRows = false, want true so unchanged updates match existing rows")
	}
}
