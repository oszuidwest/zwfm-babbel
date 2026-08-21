// Package database provides database connection utilities.
package database

import (
	"database/sql"
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	pkglogger "github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// Reserve one lock connection per worker plus automation and enqueue headroom.
const (
	lockPoolHeadroom     = 16
	lockPoolMaxIdleConns = 2
)

func mysqlDSN(cfg *config.Config) string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Database,
	)
}

// NewLockDB isolates connection-bound MySQL locks from application queries.
func NewLockDB(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("mysql", mysqlDSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("failed to open lock connection pool: %w", err)
	}
	db.SetMaxOpenConns(cfg.BulletinJobs.Workers + lockPoolHeadroom)
	db.SetMaxIdleConns(lockPoolMaxIdleConns)
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)
	return db, nil
}

// NewGormDB opens the application query pool.
func NewGormDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := mysqlDSN(cfg)

	logLevel := logger.Silent
	if cfg.Environment == config.EnvDevelopment {
		logLevel = logger.Info
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:                 logger.Default.LogMode(logLevel),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	pkglogger.Info(
		"GORM database connection established",
		"max_open_conns", cfg.Database.MaxOpenConns,
		"max_idle_conns", cfg.Database.MaxIdleConns,
		"conn_max_lifetime", cfg.Database.ConnMaxLifetime.String(),
	)

	return db, nil
}
