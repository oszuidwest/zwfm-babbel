// Package config handles application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/kelseyhightower/envconfig"
)

// Config holds all application configuration loaded from environment variables.
// Each nested config section is loaded separately to use flat BABBEL_* env var names.
type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	Auth        AuthConfig
	Audio       AudioConfig
	LogLevel    int         // Logging verbosity (4=info, 5=debug)
	Environment Environment // Runtime environment (development/production)
}

// ServerConfig holds HTTP server and CORS configuration.
type ServerConfig struct {
	Address string `envconfig:"SERVER_ADDRESS" default:":8080"`
	// AllowedOrigins is a comma-separated list of allowed origins for CORS
	AllowedOrigins string `envconfig:"ALLOWED_ORIGINS" default:""`
}

// DatabaseConfig holds MySQL database connection parameters.
type DatabaseConfig struct {
	Host           string `envconfig:"DB_HOST" default:"localhost"`
	Port           int    `envconfig:"DB_PORT" default:"3306"`
	User           string `envconfig:"DB_USER" default:"babbel"`
	Password       string `envconfig:"DB_PASSWORD" default:"babbel"`
	Database       string `envconfig:"DB_NAME" default:"babbel"`
	MigrationsPath string `ignored:"true"`
}

// AuthConfig holds authentication and session configuration.
type AuthConfig struct {
	// Method specifies authentication type: "local", "oidc", or "both"
	Method AuthMethod `envconfig:"AUTH_METHOD" default:"local"`

	// SessionSecret must be changed from default in production
	SessionSecret string `envconfig:"SESSION_SECRET" default:"your-secret-key-change-in-production"`

	// Cookie configuration
	CookieDomain   string         `envconfig:"COOKIE_DOMAIN" default:""`
	CookieSameSite CookieSameSite `envconfig:"COOKIE_SAMESITE" default:"lax"`

	// OIDC configuration
	OIDCProviderURL  string `envconfig:"OIDC_PROVIDER_URL" default:""`
	OIDCClientID     string `envconfig:"OIDC_CLIENT_ID" default:""`
	OIDCClientSecret string `envconfig:"OIDC_CLIENT_SECRET" default:""`
	OIDCRedirectURL  string `envconfig:"OIDC_REDIRECT_URL" default:"http://localhost:8080/api/v1/auth/callback"`
}

// AudioConfig holds audio processing and file storage configuration.
type AudioConfig struct {
	FFmpegPath    string `envconfig:"FFMPEG_PATH" default:"ffmpeg"`
	ProcessedPath string `envconfig:"PROCESSED_PATH" default:"./audio/processed"`
	OutputPath    string `envconfig:"OUTPUT_PATH" default:"./audio/output"`
	TempPath      string `envconfig:"TEMP_PATH" default:"./audio/temp"`
	AppRoot       string `envconfig:"APP_ROOT" default:"/app"`
}

// Load reads configuration from environment variables and creates required directories.
func Load() (*Config, error) {
	var cfg Config

	// Load each config section separately with BABBEL_ prefix
	// This avoids envconfig's default nested struct prefix behavior
	if err := envconfig.Process("BABBEL", &cfg.Server); err != nil {
		return nil, fmt.Errorf("failed to load server config: %w", err)
	}
	if err := envconfig.Process("BABBEL", &cfg.Database); err != nil {
		return nil, fmt.Errorf("failed to load database config: %w", err)
	}
	if err := envconfig.Process("BABBEL", &cfg.Auth); err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}
	if err := envconfig.Process("BABBEL", &cfg.Audio); err != nil {
		return nil, fmt.Errorf("failed to load audio config: %w", err)
	}

	// Load top-level fields
	cfg.LogLevel = 4 // default info level
	if logLevel := os.Getenv("BABBEL_LOG_LEVEL"); logLevel != "" {
		if level, err := strconv.Atoi(logLevel); err == nil {
			cfg.LogLevel = level
		}
	}
	cfg.Environment = Environment(getEnv("BABBEL_ENV", "development"))

	// Set MigrationsPath manually (not from env)
	cfg.Database.MigrationsPath = "migrations"

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

	return &cfg, nil
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

// getEnv retrieves an environment variable with a fallback default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
