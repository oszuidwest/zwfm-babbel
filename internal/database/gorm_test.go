package database

import (
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestMySQLDSNClientFoundRows(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{Database: config.DatabaseConfig{
		Host:     "localhost",
		Port:     3306,
		User:     "babbel",
		Database: "babbel",
	}}
	dsn, err := mysql.ParseDSN(mysqlDSN(cfg))
	if err != nil {
		t.Fatalf("ParseDSN(): %v", err)
	}
	if !dsn.ClientFoundRows {
		t.Fatal("ClientFoundRows = false, want true so unchanged updates match existing rows")
	}
}
