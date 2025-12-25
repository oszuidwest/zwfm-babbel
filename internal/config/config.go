// Package config handles application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Audio    AudioConfig
	// LogLevel controls logging verbosity (4=info, 5=debug)
	LogLevel    int
	Environment Environment
}

// ServerConfig holds HTTP server and CORS configuration.
type ServerConfig struct {
	Address string
	// AllowedOrigins is a comma-separated list of allowed origins for CORS
	AllowedOrigins string
}

// DatabaseConfig holds MySQL database connection parameters.
type DatabaseConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	Database       string
	MigrationsPath string
}

// AuthConfig holds authentication and session configuration.
type AuthConfig struct {
	// Method specifies authentication type: "local", "oidc", or "both"
	Method AuthMethod

	// SessionSecret must be changed from default in production
	SessionSecret string

	// Cookie configuration
	CookieDomain   string
	CookieSameSite CookieSameSite

	// OIDC configuration
	OIDCProviderURL  string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
}

// AudioConfig holds audio processing and file storage configuration.
type AudioConfig struct {
	FFmpegPath    string
	ProcessedPath string
	OutputPath    string
	TempPath      string
	AppRoot       string
}

// Load reads configuration from environment variables and creates required directories.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Address:        getEnv("BABBEL_SERVER_ADDRESS", ":8080"),
			AllowedOrigins: getEnv("BABBEL_ALLOWED_ORIGINS", ""),
		},
		Database: DatabaseConfig{
			Host:           getEnv("BABBEL_DB_HOST", "localhost"),
			Port:           getEnvInt("BABBEL_DB_PORT", 3306),
			User:           getEnv("BABBEL_DB_USER", "babbel"),
			Password:       getEnv("BABBEL_DB_PASSWORD", "babbel"),
			Database:       getEnv("BABBEL_DB_NAME", "babbel"),
			MigrationsPath: "migrations",
		},
		Auth: AuthConfig{
			Method:           AuthMethod(getEnv("BABBEL_AUTH_METHOD", "local")),
			SessionSecret:    getEnv("BABBEL_SESSION_SECRET", "your-secret-key-change-in-production"),
			CookieDomain:     getEnv("BABBEL_COOKIE_DOMAIN", ""),
			CookieSameSite:   CookieSameSite(getEnv("BABBEL_COOKIE_SAMESITE", "lax")),
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
			AppRoot:       getEnv("BABBEL_APP_ROOT", "/app"),
		},
		LogLevel:    4, // info level
		Environment: Environment(getEnv("BABBEL_ENV", "development")),
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

// getEnv returns the value of the environment variable key, or defaultValue if unset.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns the value of the environment variable key as an integer, or defaultValue if unset or invalid.
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// Validate checks the configuration for required values and valid settings.
// Returns an error if any required configuration is missing or invalid.
func (c *Config) Validate() error {
	// Enum validations
	if !c.Auth.Method.IsValid() {
		return fmt.Errorf("invalid auth method: %s (must be local, oidc, or both)", c.Auth.Method)
	}

	if !c.Environment.IsValid() {
		return fmt.Errorf("invalid environment: %s (must be development or production)", c.Environment)
	}

	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d (must be 1-65535)", c.Database.Port)
	}

	// Session secret validation (32 chars required for security)
	if len(c.Auth.SessionSecret) < 32 {
		return fmt.Errorf("BABBEL_SESSION_SECRET must be at least 32 characters (got %d)", len(c.Auth.SessionSecret))
	}

	// Check for default/insecure session secret in production
	if c.Environment == EnvProduction && c.Auth.SessionSecret == "your-secret-key-change-in-production" {
		return errors.New("BABBEL_SESSION_SECRET must be changed from default value in production")
	}

	// OIDC validation when OAuth is enabled
	if c.Auth.Method.SupportsOIDC() {
		if c.Auth.OIDCProviderURL == "" {
			return errors.New("BABBEL_OIDC_PROVIDER_URL required when auth method is 'oidc' or 'both'")
		}
		if c.Auth.OIDCClientID == "" {
			return errors.New("BABBEL_OIDC_CLIENT_ID required when auth method is 'oidc' or 'both'")
		}
		if c.Auth.OIDCClientSecret == "" {
			return errors.New("BABBEL_OIDC_CLIENT_SECRET required when auth method is 'oidc' or 'both'")
		}
	}

	// FFmpeg binary validation
	if _, err := exec.LookPath(c.Audio.FFmpegPath); err != nil {
		return fmt.Errorf("FFmpeg binary not found at '%s': ensure FFmpeg is installed and in PATH", c.Audio.FFmpegPath)
	}

	return nil
}
