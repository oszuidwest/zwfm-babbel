// Package config handles application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/caarlos0/env/v11"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server holds HTTP server and CORS configuration.
	Server ServerConfig
	// Database holds database connection settings.
	Database DatabaseConfig `envPrefix:"DB_"`
	// Auth holds authentication and session configuration.
	Auth AuthConfig
	// Audio holds audio processing and file storage paths.
	Audio AudioConfig
	// LogLevel sets the logging verbosity level (0-5, default: 4).
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment specifies the runtime environment (development or production).
	Environment Environment `env:"ENV" envDefault:"development"`
}

// ServerConfig holds HTTP server and CORS configuration.
type ServerConfig struct {
	// Address is the HTTP server listen address (default: ":8080").
	Address string `env:"SERVER_ADDRESS" envDefault:":8080"`
	// AllowedOrigins is a comma-separated list of CORS allowed origins.
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`
}

// DatabaseConfig holds MySQL database connection parameters.
type DatabaseConfig struct {
	// Host is the MySQL server hostname or IP address.
	Host string `env:"HOST" envDefault:"localhost"`
	// Port is the MySQL server port number (default: 3306).
	Port int `env:"PORT" envDefault:"3306"`
	// User is the MySQL database username.
	User string `env:"USER" envDefault:"babbel"`
	// Password is the MySQL database password.
	Password string `env:"PASSWORD" envDefault:"babbel"`
	// Database is the MySQL database name.
	Database string `env:"NAME" envDefault:"babbel"`
	// MigrationsPath is the filesystem path to database migration files.
	MigrationsPath string `env:"-"`
}

// AuthConfig holds authentication and session configuration.
type AuthConfig struct {
	// Method specifies the authentication method (local, oidc, or both).
	Method AuthMethod `env:"AUTH_METHOD" envDefault:"local"`
	// SessionSecret is the secret key for session encryption (min 32 characters).
	SessionSecret string `env:"SESSION_SECRET" envDefault:"your-secret-key-change-in-production"`
	// CookieDomain is the domain scope for session cookies.
	CookieDomain string `env:"COOKIE_DOMAIN"`
	// CookieSameSite controls the SameSite attribute for session cookies (strict, lax, or none).
	CookieSameSite CookieSameSite `env:"COOKIE_SAMESITE" envDefault:"lax"`
	// OIDCProviderURL is the OpenID Connect provider's base URL.
	OIDCProviderURL string `env:"OIDC_PROVIDER_URL"`
	// OIDCClientID is the OAuth/OIDC client identifier.
	OIDCClientID string `env:"OIDC_CLIENT_ID"`
	// OIDCClientSecret is the OAuth/OIDC client secret.
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET"`
	// OIDCRedirectURL is the OAuth callback URL for this application.
	OIDCRedirectURL string `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/api/v1/auth/callback"`
}

// AudioConfig holds audio processing and file storage configuration.
type AudioConfig struct {
	// FFmpegPath is the path to the FFmpeg binary executable.
	FFmpegPath string `env:"FFMPEG_PATH" envDefault:"ffmpeg"`
	// ProcessedPath is the directory for processed audio files.
	ProcessedPath string `env:"PROCESSED_PATH" envDefault:"./audio/processed"`
	// OutputPath is the directory for generated bulletin output files.
	OutputPath string `env:"OUTPUT_PATH" envDefault:"./audio/output"`
	// TempPath is the directory for temporary audio processing files.
	TempPath string `env:"TEMP_PATH" envDefault:"./audio/temp"`
	// AppRoot is the application root directory path.
	AppRoot string `env:"APP_ROOT" envDefault:"/app"`
}

// Load reads configuration from environment variables and creates required directories.
func Load() (*Config, error) {
	cfg, err := env.ParseAsWithOptions[Config](env.Options{
		Prefix: "BABBEL_",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set non-env fields
	cfg.Database.MigrationsPath = "migrations"

	// Create required directories
	dirs := []string{
		cfg.Audio.ProcessedPath,
		cfg.Audio.OutputPath,
		cfg.Audio.TempPath,
		"./uploads",
	}
	for _, dir := range dirs {
		// #nosec G301 - 0755 is appropriate for audio directories
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &cfg, nil
}

// Validate checks the configuration for required values and valid settings.
func (c *Config) Validate() error {
	if !c.Auth.Method.IsValid() {
		return fmt.Errorf("invalid auth method: %s (must be local, oidc, or both)", c.Auth.Method)
	}

	if !c.Environment.IsValid() {
		return fmt.Errorf("invalid environment: %s (must be development or production)", c.Environment)
	}

	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d (must be 1-65535)", c.Database.Port)
	}

	if len(c.Auth.SessionSecret) < 32 {
		return fmt.Errorf("BABBEL_SESSION_SECRET must be at least 32 characters (got %d)", len(c.Auth.SessionSecret))
	}

	if c.Environment == EnvProduction && c.Auth.SessionSecret == "your-secret-key-change-in-production" {
		return errors.New("BABBEL_SESSION_SECRET must be changed from default value in production")
	}

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

	if _, err := exec.LookPath(c.Audio.FFmpegPath); err != nil {
		return fmt.Errorf("FFmpeg binary not found at '%s': ensure FFmpeg is installed and in PATH", c.Audio.FFmpegPath)
	}

	return nil
}
