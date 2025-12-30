// Package config handles application configuration management.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

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
	// Automation holds radio automation integration configuration.
	Automation AutomationConfig
	// LogLevel sets the logging verbosity level (0-5, default: 4).
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment specifies the runtime environment (development or production).
	Environment Environment `env:"ENV" envDefault:"development"`
}

// AutomationConfig holds configuration for radio automation system integration.
type AutomationConfig struct {
	// Key is the API key for public bulletin access by automation systems.
	// If empty, the public bulletin endpoint is disabled (returns 404).
	Key string `env:"AUTOMATION_KEY"`
	// GenerationTimeout is the maximum time allowed for bulletin generation (default: 120s).
	GenerationTimeout time.Duration `env:"AUTOMATION_TIMEOUT" envDefault:"120s"`
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
	// MaxOpenConns is the maximum number of open connections to the database.
	MaxOpenConns int `env:"MAX_OPEN_CONNS" envDefault:"25"`
	// MaxIdleConns is the maximum number of idle connections to the database.
	MaxIdleConns int `env:"MAX_IDLE_CONNS" envDefault:"5"`
	// ConnMaxLifetime is the maximum lifetime of a database connection.
	ConnMaxLifetime time.Duration `env:"CONN_MAX_LIFETIME" envDefault:"5m"`
}

// LocalAuthConfig holds password policy and lockout configuration for local authentication.
type LocalAuthConfig struct {
	// MinPasswordLength is the minimum required password length (default: 8).
	MinPasswordLength int `env:"MIN_PASSWORD_LENGTH" envDefault:"8"`
	// RequireUppercase requires at least one uppercase letter in passwords (default: true).
	RequireUppercase bool `env:"REQUIRE_UPPERCASE" envDefault:"true"`
	// RequireLowercase requires at least one lowercase letter in passwords (default: true).
	RequireLowercase bool `env:"REQUIRE_LOWERCASE" envDefault:"true"`
	// RequireNumber requires at least one number in passwords (default: true).
	RequireNumber bool `env:"REQUIRE_NUMBER" envDefault:"true"`
	// RequireSpecialChar requires at least one special character in passwords (default: false).
	RequireSpecialChar bool `env:"REQUIRE_SPECIAL" envDefault:"false"`
	// MaxLoginAttempts is the maximum number of failed login attempts before lockout (default: 5).
	MaxLoginAttempts int `env:"MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	// LockoutDurationMinutes is the account lockout duration in minutes (default: 15).
	LockoutDurationMinutes int `env:"LOCKOUT_MINUTES" envDefault:"15"`
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
	// Local holds local authentication password policy and lockout configuration.
	Local LocalAuthConfig `envPrefix:"AUTH_"`
}

// AudioConfig holds audio processing and file storage configuration.
type AudioConfig struct {
	// FFmpegPath is the path to the FFmpeg binary executable.
	FFmpegPath string `env:"FFMPEG_PATH" envDefault:"ffmpeg"`
	// FFprobePath is the path to the FFprobe binary executable.
	FFprobePath string `env:"FFPROBE_PATH" envDefault:"ffprobe"`
	// ProcessedPath is the directory for processed audio files.
	ProcessedPath string `env:"PROCESSED_PATH" envDefault:"./audio/processed"`
	// OutputPath is the directory for generated bulletin output files.
	OutputPath string `env:"OUTPUT_PATH" envDefault:"./audio/output"`
	// TempPath is the directory for temporary audio processing files.
	TempPath string `env:"TEMP_PATH" envDefault:"./audio/temp"`
	// AppRoot is the application root directory path.
	AppRoot string `env:"APP_ROOT" envDefault:"/app"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg, err := env.ParseAsWithOptions[Config](env.Options{
		Prefix: "BABBEL_",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set non-env fields
	cfg.Database.MigrationsPath = "migrations"

	return &cfg, nil
}

// EnsureDirectories creates all required application directories.
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.Audio.ProcessedPath,
		c.Audio.OutputPath,
		c.Audio.TempPath,
		"./uploads",
	}
	for _, dir := range dirs {
		// #nosec G301 - 0755 is appropriate for audio directories
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
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
