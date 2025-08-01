// Package config provides configuration loading and management.
package config

import (
	"fmt"
	"os"
)

// Config holds all application configuration.
type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	Auth        AuthConfig
	Audio       AudioConfig
	LogLevel    int
	Environment string
}

// ServerConfig holds server-related configuration.
type ServerConfig struct {
	Address        string
	AllowedOrigins string // Comma-separated list of allowed origins for CORS
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	Database       string
	MigrationsPath string
}

// AuthConfig holds authentication-related configuration.
type AuthConfig struct {
	// Authentication method: "local", "oidc", or "both"
	Method string

	// Session secret key
	SessionSecret string

	// OIDC configuration (for Azure AD, Google, etc.)
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
}

// AudioConfig holds audio processing configuration.
type AudioConfig struct {
	FFmpegPath    string
	ProcessedPath string
	OutputPath    string
	TempPath      string
}

// Load creates a simple config with environment variables and sensible defaults
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Address:        getEnv("BABBEL_SERVER_ADDRESS", ":8080"),
			AllowedOrigins: getEnv("BABBEL_ALLOWED_ORIGINS", ""),
		},
		Database: DatabaseConfig{
			Host:           getEnv("BABBEL_DB_HOST", "localhost"),
			Port:           3306,
			User:           getEnv("BABBEL_DB_USER", "babbel"),
			Password:       getEnv("BABBEL_DB_PASSWORD", "babbel"),
			Database:       getEnv("BABBEL_DB_NAME", "babbel"),
			MigrationsPath: "migrations",
		},
		Auth: AuthConfig{
			Method:           getEnv("BABBEL_AUTH_METHOD", "local"),
			SessionSecret:    getEnv("BABBEL_SESSION_SECRET", "your-secret-key-change-in-production"),
			OIDCProviderURL:  getEnv("BABBEL_OIDC_PROVIDER_URL", ""),
			OIDCClientID:     getEnv("BABBEL_OIDC_CLIENT_ID", ""),
			OIDCClientSecret: getEnv("BABBEL_OIDC_CLIENT_SECRET", ""),
			OIDCRedirectURL:  getEnv("BABBEL_OIDC_REDIRECT_URL", "http://localhost:8080/api/v1/auth/callback"),
		},
		Audio: AudioConfig{
			FFmpegPath:    getEnv("BABBEL_FFMPEG_PATH", "ffmpeg"),
			ProcessedPath: getEnv("BABBEL_PROCESSED_PATH", "./audio/processed"),
			OutputPath:    getEnv("BABBEL_OUTPUT_PATH", "./audio/output"),
			TempPath:      getEnv("BABBEL_TEMP_PATH", "./audio/temp"),
		},
		LogLevel:    4, // info level
		Environment: getEnv("BABBEL_ENV", "development"),
	}

	// Create directories if they don't exist
	dirs := []string{
		cfg.Audio.ProcessedPath,
		cfg.Audio.OutputPath,
		cfg.Audio.TempPath,
		"./uploads",
	}

	for _, dir := range dirs {
		// #nosec G301 - 0755 is appropriate for audio directories that need to be readable by web server
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return cfg, nil
}

// getEnv gets environment variable with default fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
