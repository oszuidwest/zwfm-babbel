// Package main is the entry point for the Babbel API server.
package main

import (
	"context"
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
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Log configuration (without sensitive data)
	log.Printf("Database config: Host=%s, Port=%d, User=%s, Database=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Database)
	log.Printf("Server config: Address=%s", cfg.Server.Address)

	// Initialize logger
	logLevel := "info"
	if cfg.LogLevel >= 5 {
		logLevel = "debug"
	}

	if err := logger.Initialize(logLevel, true); err != nil {
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

	// Migrations are run manually via make db-reset to prevent accidental schema changes

	// Setup API router
	router := api.SetupRouter(db, cfg)

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Address,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting Babbel API server on %s", cfg.Server.Address)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server: %v", err)
		}
	}()

	// Start story expiration scheduler
	expirationService := scheduler.NewStoryExpirationService(db)
	expirationService.Start()
	defer expirationService.Stop()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	logger.Info("Shutting down server...")

	// Stop scheduler first
	expirationService.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exited")
}
