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

// Config contains all application settings loaded from environment variables.
type Config struct {
	// Server configures HTTP server and CORS settings.
	Server ServerConfig
	// Database configures database connection settings.
	Database DatabaseConfig `envPrefix:"DB_"`
	// Auth configures authentication and session settings.
	Auth AuthConfig
	// Audio configures audio processing and file storage paths.
	Audio AudioConfig
	// Automation configures radio automation integration.
	Automation AutomationConfig
	// LogLevel sets the logging verbosity level (0-5, default: 4).
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment specifies the runtime environment (development or production).
	Environment Environment `env:"ENV" envDefault:"development"`
}

// AutomationConfig defines settings for radio automation system integration.
type AutomationConfig struct {
	// Key authenticates automation system requests. Empty disables the endpoint.
	Key string `env:"AUTOMATION_KEY"`
	// GenerationTimeout limits bulletin generation duration (default: 120s).
	GenerationTimeout time.Duration `env:"AUTOMATION_TIMEOUT" envDefault:"120s"`
}

// ServerConfig defines HTTP server and CORS settings.
type ServerConfig struct {
	// Address specifies the HTTP server listen address (default: ":8080").
	Address string `env:"SERVER_ADDRESS" envDefault:":8080"`
	// AllowedOrigins lists CORS-permitted origins as comma-separated values.
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`
}

// DatabaseConfig defines MySQL database connection parameters.
type DatabaseConfig struct {
	// Host specifies the MySQL server hostname or IP address.
	Host string `env:"HOST" envDefault:"localhost"`
	// Port specifies the MySQL server port number (default: 3306).
	Port int `env:"PORT" envDefault:"3306"`
	// User specifies the MySQL database username.
	User string `env:"USER" envDefault:"babbel"`
	// Password specifies the MySQL database password.
	Password string `env:"PASSWORD" envDefault:"babbel"` //nolint:gosec // G117: env config, no JSON serialization
	// Database specifies the MySQL database name.
	Database string `env:"NAME" envDefault:"babbel"`
	// MigrationsPath specifies the filesystem path to migration files.
	MigrationsPath string `env:"-"`
	// MaxOpenConns limits open database connections (default: 25).
	MaxOpenConns int `env:"MAX_OPEN_CONNS" envDefault:"25"`
	// MaxIdleConns limits idle database connections (default: 5).
	MaxIdleConns int `env:"MAX_IDLE_CONNS" envDefault:"5"`
	// ConnMaxLifetime limits database connection lifetime (default: 5m).
	ConnMaxLifetime time.Duration `env:"CONN_MAX_LIFETIME" envDefault:"5m"`
}

// LocalAuthConfig defines password policy and lockout rules for local authentication.
type LocalAuthConfig struct {
	// MinPasswordLength sets the minimum required password length (default: 8).
	MinPasswordLength int `env:"MIN_PASSWORD_LENGTH" envDefault:"8"`
	// RequireUppercase enforces uppercase letter requirement (default: true).
	RequireUppercase bool `env:"REQUIRE_UPPERCASE" envDefault:"true"`
	// RequireLowercase enforces lowercase letter requirement (default: true).
	RequireLowercase bool `env:"REQUIRE_LOWERCASE" envDefault:"true"`
	// RequireNumber enforces numeric character requirement (default: true).
	RequireNumber bool `env:"REQUIRE_NUMBER" envDefault:"true"`
	// RequireSpecialChar enforces special character requirement (default: false).
	RequireSpecialChar bool `env:"REQUIRE_SPECIAL" envDefault:"false"`
	// MaxLoginAttempts limits failed attempts before lockout (default: 5).
	MaxLoginAttempts int `env:"MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	// LockoutDurationMinutes sets account lockout duration (default: 15).
	LockoutDurationMinutes int `env:"LOCKOUT_MINUTES" envDefault:"15"`
}

// AuthConfig defines authentication and session settings.
type AuthConfig struct {
	// Method specifies the authentication method (local, oidc, or both).
	Method AuthMethod `env:"AUTH_METHOD" envDefault:"local"`
	// SessionSecret provides the key for session encryption (min 32 characters).
	SessionSecret string `env:"SESSION_SECRET" envDefault:"your-secret-key-change-in-production"` //nolint:gosec // G117: env config, no JSON serialization
	// CookieDomain sets the domain scope for session cookies.
	CookieDomain string `env:"COOKIE_DOMAIN"`
	// CookieSameSite controls the SameSite cookie attribute (strict, lax, or none).
	CookieSameSite CookieSameSite `env:"COOKIE_SAMESITE" envDefault:"lax"`
	// OIDCProviderURL specifies the OpenID Connect provider's base URL.
	OIDCProviderURL string `env:"OIDC_PROVIDER_URL"`
	// OIDCClientID specifies the OAuth/OIDC client identifier.
	OIDCClientID string `env:"OIDC_CLIENT_ID"`
	// OIDCClientSecret specifies the OAuth/OIDC client secret.
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET"`
	// OIDCRedirectURL specifies the OAuth callback URL for this application.
	OIDCRedirectURL string `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/api/v1/auth/callback"`
	// Local configures password policy and lockout rules.
	Local LocalAuthConfig `envPrefix:"AUTH_"`
}

// AudioConfig defines audio processing and file storage settings.
type AudioConfig struct {
	// FFmpegPath specifies the path to the FFmpeg binary.
	FFmpegPath string `env:"FFMPEG_PATH" envDefault:"ffmpeg"`
	// FFprobePath specifies the path to the FFprobe binary.
	FFprobePath string `env:"FFPROBE_PATH" envDefault:"ffprobe"`
	// ProcessedPath specifies the directory for processed audio files.
	ProcessedPath string `env:"PROCESSED_PATH" envDefault:"./audio/processed"`
	// OutputPath specifies the directory for generated bulletin files.
	OutputPath string `env:"OUTPUT_PATH" envDefault:"./audio/output"`
	// TempPath specifies the directory for temporary audio files.
	TempPath string `env:"TEMP_PATH" envDefault:"./audio/temp"`
	// AppRoot specifies the application root directory path.
	AppRoot string `env:"APP_ROOT" envDefault:"/app"`
	// BulletinRetention is how long bulletin audio files are kept before cleanup (default: 7 days).
	BulletinRetention time.Duration `env:"BULLETIN_RETENTION" envDefault:"168h"`
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
