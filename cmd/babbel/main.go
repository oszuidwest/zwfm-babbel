// Package main is the entry point for the Babbel API server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/database"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/scheduler"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"github.com/oszuidwest/zwfm-babbel/pkg/version"
	"gorm.io/gorm"
)

const (
	debugLogLevel            = 5
	serverReadTimeout        = 15 * time.Second
	serverWriteTimeout       = 15 * time.Second
	serverIdleTimeout        = 60 * time.Second
	shutdownTimeout          = 30 * time.Second
	fatalNotificationTimeout = 30 * time.Second
)

func main() {
	if handleVersionFlag() {
		return
	}
	if err := run(); err != nil {
		log.Printf("Babbel stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	alerts := notify.New(&cfg.Notifications)
	defer alerts.Close()

	if err := validateConfig(cfg); err != nil {
		notifyCritical(alerts, "startup:configuration", "Babbel configuration failed", err)
		return err
	}
	if err := initLogger(cfg); err != nil {
		notifyCritical(alerts, "startup:logger", "Babbel logger initialization failed", err)
		return err
	}
	defer logger.Sync()
	if alerts.IsConfigured() {
		logger.Info("Microsoft Graph e-mail notifications configured")
	} else {
		logger.Warn("E-mail notifications are not configured; operational failures will only be logged")
	}

	db, err := database.NewGormDB(cfg)
	if err != nil {
		notifyCritical(alerts, "startup:database", "Babbel database startup failed", err)
		return fmt.Errorf("connect to database: %w", err)
	}
	defer closeDatabase(db, alerts)

	router, err := api.SetupRouter(db, cfg, alerts)
	if err != nil {
		notifyCritical(alerts, "startup:router", "Babbel router or authentication startup failed", err)
		return fmt.Errorf("setup router: %w", err)
	}

	srv := newServer(cfg, router)
	serverErr := startServer(srv, cfg)

	expirationService := scheduler.NewStoryExpirationService(db, alerts)
	expirationService.Start()

	cleanupService := scheduler.NewBulletinCleanupService(db, cfg, alerts)
	cleanupService.Start()

	databaseHealthService := scheduler.NewDatabaseHealthService(db, alerts)
	databaseHealthService.Start()

	serveErr := waitForShutdown(serverErr)

	logger.Info("Shutting down server...")
	databaseHealthService.Stop()
	cleanupService.Stop()
	expirationService.Stop()
	shutdownErr := shutdownServer(srv)
	logger.Info("Server exited")

	if serveErr != nil {
		notifyCritical(alerts, "runtime:http-server", "Babbel HTTP server stopped unexpectedly", serveErr)
	}
	if shutdownErr != nil {
		notifyCritical(alerts, "shutdown:http-server", "Babbel graceful shutdown failed", shutdownErr)
	}
	return errors.Join(serveErr, shutdownErr)
}

func handleVersionFlag() bool {
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()
	if *showVersion {
		fmt.Printf("babbel %s (commit: %s, built: %s)\n", version.Version, version.Commit, version.BuildTime)
		return true
	}
	return false
}

func validateConfig(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	if err := cfg.EnsureDirectories(); err != nil {
		return fmt.Errorf("create application directories: %w", err)
	}
	log.Printf("Database config: Host=%s, Port=%d, User=%s, Database=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Database)
	log.Printf("Server config: Address=%s", cfg.Server.Address)
	return nil
}

func initLogger(cfg *config.Config) error {
	logLevel := "info"
	if cfg.LogLevel >= debugLogLevel {
		logLevel = "debug"
	}
	if err := logger.Initialize(logLevel, cfg.Environment == config.EnvDevelopment); err != nil {
		return fmt.Errorf("initialize logger: %w", err)
	}
	return nil
}

func closeDatabase(db *gorm.DB, alerts *notify.Service) {
	sqlDB, err := db.DB()
	if err != nil {
		logger.Error("Failed to get underlying database connection", "error", err)
		notifyCritical(alerts, "shutdown:database", "Babbel database shutdown failed", err)
		return
	}
	if err := sqlDB.Close(); err != nil {
		logger.Error("Failed to close database connection", "error", err)
		notifyCritical(alerts, "shutdown:database", "Babbel database shutdown failed", err)
	}
}

func newServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      handler,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}
}

func startServer(srv *http.Server, cfg *config.Config) <-chan error {
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Starting Babbel API server", "address", cfg.Server.Address, "version", version.Version, "commit", version.Commit)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()
	return serverErr
}

func waitForShutdown(serverErr <-chan error) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)
	select {
	case <-quit:
		return nil
	case err := <-serverErr:
		return err
	}
}

func shutdownServer(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		return err
	}
	return nil
}

func notifyCritical(alerts *notify.Service, key, summary string, err error) {
	if err == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), fatalNotificationTimeout)
	defer cancel()
	if sendErr := alerts.AlertSync(ctx, notify.Event{
		Key: key, Summary: summary, Details: err.Error(), Kind: notify.KindImmediate,
	}); sendErr != nil {
		log.Printf("Failed to send critical notification: %v", sendErr)
	}
}
