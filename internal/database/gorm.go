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

// mysqlDSN runs the session in UTC. MySQL then sends and reads TIMESTAMP
// values as UTC; local wall-clock time would repeat an hour at the autumn
// clock change and shift values written in that hour.
func mysqlDSN(cfg *config.Config) string {
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=True&loc=UTC&time_zone=%%27%%2B00%%3A00%%27&clientFoundRows=true&timeout=%s&readTimeout=%s&writeTimeout=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Database,
		cfg.Database.ConnectTimeout, cfg.Database.ReadTimeout, cfg.Database.WriteTimeout,
	)
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
	// A request can hold several connections at once. Keeping them all idle
	// avoids a reconnect for each connection above the limit during a burst.
	sqlDB.SetMaxIdleConns(cfg.Database.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	pkglogger.Info(
		"GORM database connection established",
		"max_open_conns", cfg.Database.MaxOpenConns,
		"conn_max_lifetime", cfg.Database.ConnMaxLifetime.String(),
	)

	return db, nil
}
