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
	Server      ServerConfig
	Database    DatabaseConfig `envPrefix:"DB_"`
	Auth        AuthConfig
	Audio       AudioConfig
	LogLevel    int         `env:"LOG_LEVEL" envDefault:"4"`
	Environment Environment `env:"ENV" envDefault:"development"`
}

// ServerConfig holds HTTP server and CORS configuration.
type ServerConfig struct {
	Address        string `env:"SERVER_ADDRESS" envDefault:":8080"`
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`
}

// DatabaseConfig holds MySQL database connection parameters.
type DatabaseConfig struct {
	Host           string `env:"HOST" envDefault:"localhost"`
	Port           int    `env:"PORT" envDefault:"3306"`
	User           string `env:"USER" envDefault:"babbel"`
	Password       string `env:"PASSWORD" envDefault:"babbel"`
	Database       string `env:"NAME" envDefault:"babbel"`
	MigrationsPath string `env:"-"`
}

// AuthConfig holds authentication and session configuration.
type AuthConfig struct {
	Method           AuthMethod     `env:"AUTH_METHOD" envDefault:"local"`
	SessionSecret    string         `env:"SESSION_SECRET" envDefault:"your-secret-key-change-in-production"`
	CookieDomain     string         `env:"COOKIE_DOMAIN"`
	CookieSameSite   CookieSameSite `env:"COOKIE_SAMESITE" envDefault:"lax"`
	OIDCProviderURL  string         `env:"OIDC_PROVIDER_URL"`
	OIDCClientID     string         `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string         `env:"OIDC_CLIENT_SECRET"`
	OIDCRedirectURL  string         `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/api/v1/auth/callback"`
}

// AudioConfig holds audio processing and file storage configuration.
type AudioConfig struct {
	FFmpegPath    string `env:"FFMPEG_PATH" envDefault:"ffmpeg"`
	ProcessedPath string `env:"PROCESSED_PATH" envDefault:"./audio/processed"`
	OutputPath    string `env:"OUTPUT_PATH" envDefault:"./audio/output"`
	TempPath      string `env:"TEMP_PATH" envDefault:"./audio/temp"`
	AppRoot       string `env:"APP_ROOT" envDefault:"/app"`
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
