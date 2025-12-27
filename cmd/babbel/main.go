// Package main is the entry point for the Babbel API server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/database"
	"github.com/oszuidwest/zwfm-babbel/internal/scheduler"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"github.com/oszuidwest/zwfm-babbel/pkg/version"
)

const (
	debugLogLevel           = 5
	serverReadTimeout       = 15 * time.Second
	serverWriteTimeout      = 15 * time.Second
	serverIdleTimeout       = 60 * time.Second
	serverStartupCheckDelay = 100 * time.Millisecond
	shutdownTimeout         = 30 * time.Second
)

func main() {
	if handleVersionFlag() {
		return
	}

	cfg := mustLoadConfig()
	initLogger(cfg)
	defer logger.Sync()

	db, err := database.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer closeDatabase(db)

	router, err := api.SetupRouter(db, cfg)
	if err != nil {
		logger.Fatal("Failed to setup router: %v", err)
	}

	srv := newServer(cfg, router)
	startServer(srv, cfg)

	expirationService := scheduler.NewStoryExpirationService(db)
	expirationService.Start()

	waitForShutdown()

	logger.Info("Shutting down server...")
	expirationService.Stop()
	shutdownServer(srv)
	logger.Info("Server exited")
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

func mustLoadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}
	if err := cfg.EnsureDirectories(); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}
	log.Printf("Database config: Host=%s, Port=%d, User=%s, Database=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Database)
	log.Printf("Server config: Address=%s", cfg.Server.Address)
	return cfg
}

func initLogger(cfg *config.Config) {
	logLevel := "info"
	if cfg.LogLevel >= debugLogLevel {
		logLevel = "debug"
	}
	if err := logger.Initialize(logLevel, cfg.Environment == config.EnvDevelopment); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
}

func closeDatabase(db io.Closer) {
	if err := db.Close(); err != nil {
		logger.Error("Failed to close database connection: %v", err)
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

func startServer(srv *http.Server, cfg *config.Config) {
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("Starting Babbel API server on %s (version: %s, commit: %s)", cfg.Server.Address, version.Version, version.Commit)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			logger.Fatal("Failed to start server: %v", err)
		}
	case <-time.After(serverStartupCheckDelay):
	}
}

func waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}

func shutdownServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown: %v", err)
	}
}
