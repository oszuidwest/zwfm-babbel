// Package main is the entry point for the Babbel API server.
package main

import (
	"context"
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
	// Parse command line flags
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Show version if requested
	if *showVersion {
		fmt.Printf("babbel %s (commit: %s, built: %s)\n", version.Version, version.Commit, version.BuildTime)
		os.Exit(0)
	}
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Create required directories
	if err := cfg.EnsureDirectories(); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Log configuration (without sensitive data)
	log.Printf("Database config: Host=%s, Port=%d, User=%s, Database=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Database)
	log.Printf("Server config: Address=%s", cfg.Server.Address)

	// Initialize logger
	logLevel := "info"
	if cfg.LogLevel >= debugLogLevel {
		logLevel = "debug"
	}
	isDev := cfg.Environment == config.EnvDevelopment

	if err := logger.Initialize(logLevel, isDev); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	// Connect to database
	db, err := database.Connect(cfg.Database)
	if err != nil {
		logger.Fatal("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("Failed to close database connection: %v", err)
		}
	}()

	// Setup API router
	router, err := api.SetupRouter(db, cfg)
	if err != nil {
		logger.Fatal("Failed to setup router: %v", err)
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,
	}

	// Create error channel for server startup
	serverErr := make(chan error, 1)

	// Start server in goroutine
	go func() {
		logger.Info("Starting Babbel API server on %s (version: %s, commit: %s)", cfg.Server.Address, version.Version, version.Commit)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Give the server a moment to fail on port binding issues
	select {
	case err := <-serverErr:
		if err != nil {
			logger.Fatal("Failed to start server: %v", err)
		}
	case <-time.After(serverStartupCheckDelay):
		// Server started successfully, continue
	}

	// Start story expiration scheduler
	// Note: Start() returns void, no error to check
	expirationService := scheduler.NewStoryExpirationService(db)
	expirationService.Start()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	logger.Info("Shutting down server...")

	// Stop scheduler first
	// Note: Stop() returns void, no error to check
	expirationService.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}
