// Package database provides database connection utilities.
package database

import (
	"fmt"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	pkglogger "github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// NewGormDB creates a new GORM database connection using the provided configuration.
func NewGormDB(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Database,
	)

	logLevel := logger.Silent
	if cfg.Environment == "development" {
		logLevel = logger.Info
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:                 logger.Default.LogMode(logLevel),
		SkipDefaultTransaction: true, // Better performance for read operations
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
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
