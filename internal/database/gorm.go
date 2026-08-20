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

// Lock pool sizing: each held named lock pins one connection for as long as
// it is held (up to a full bulletin generation), so the pool must fit every
// concurrent lock holder. It is sized as all configured bulletin workers plus
// headroom for automation-endpoint generations and short-lived enqueue locks.
// Acquirers past the cap wait inside this pool, bounded by their lock wait,
// and can never starve the query pool.
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

// NewLockDB opens a dedicated connection pool for MySQL named locks. Advisory
// locks pin their connection for as long as they are held, so sharing the
// query pool would let lock holders starve regular queries of connections —
// with BABBEL_DB_MAX_OPEN_CONNS=1 that deadlocks outright, since the queries
// the lock protects then wait forever on the connection the lock pins.
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

// NewGormDB creates a new GORM database connection using the provided configuration.
func NewGormDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := mysqlDSN(cfg)

	logLevel := logger.Silent
	if cfg.Environment == config.EnvDevelopment {
		logLevel = logger.Info
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:                 logger.Default.LogMode(logLevel),
		SkipDefaultTransaction: true, // Better performance for read operations
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure the connection pool.
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
