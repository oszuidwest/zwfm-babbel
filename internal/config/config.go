// Package config loads and validates application configuration.
package config

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const audioToolVersionCheckTimeout = 5 * time.Second

// Config is the environment-backed runtime configuration.
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
	// TTS configures text-to-speech integration with ElevenLabs.
	TTS TTSConfig `envPrefix:"ELEVENLABS_"`
	// Notifications configures operational alert e-mails.
	Notifications NotificationConfig `envPrefix:"NOTIFICATIONS_"`
	// LogLevel sets the logging verbosity level (0-5, default: 4).
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment specifies the runtime environment (development or production).
	Environment Environment `env:"ENV" envDefault:"development"`
	// FrontendURL is the frontend base URL used for OAuth redirects.
	FrontendURL string `env:"FRONTEND_URL"`
}

// NotificationConfig defines alert delivery and duplicate-suppression policy.
type NotificationConfig struct {
	// Email configures Microsoft Graph mail delivery.
	Email GraphConfig `envPrefix:"EMAIL_"`
	// Cooldown suppresses duplicate e-mails for an active alert key.
	Cooldown time.Duration `env:"COOLDOWN" envDefault:"1h"`
	// FailureThreshold is the number of transient failures required in FailureWindow.
	FailureThreshold int `env:"FAILURE_THRESHOLD" envDefault:"3"`
	// FailureWindow limits how far apart transient failures may occur.
	FailureWindow time.Duration `env:"FAILURE_WINDOW" envDefault:"10m"`
}

// GraphConfig defines Microsoft Graph client-credentials mail settings.
type GraphConfig struct {
	TenantID     string `env:"TENANT_ID"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	FromAddress  string `env:"FROM_ADDRESS"`
	Recipients   string `env:"RECIPIENTS"`
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
	Password string `env:"PASSWORD" envDefault:"babbel"`
	// Database specifies the MySQL database name.
	Database string `env:"NAME" envDefault:"babbel"`
	// MigrationsPath specifies the filesystem path to migration files.
	MigrationsPath string `env:"-"`
	// MaxOpenConns limits open database connections (default: 100).
	MaxOpenConns int `env:"MAX_OPEN_CONNS" envDefault:"100"`
	// MaxIdleConns limits idle database connections (default: 10).
	MaxIdleConns int `env:"MAX_IDLE_CONNS" envDefault:"10"`
	// ConnMaxLifetime limits database connection lifetime (default: 1h).
	ConnMaxLifetime time.Duration `env:"CONN_MAX_LIFETIME" envDefault:"1h"`
}

// LocalAuthConfig defines password policy and lockout rules for local authentication.
type LocalAuthConfig struct {
	// MinPasswordLength sets the minimum required password length (8-128, default: 8).
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
	SessionSecret string `env:"SESSION_SECRET" envDefault:"your-secret-key-change-in-production"`
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
	OIDCRedirectURL string `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/api/v1/auth/oauth/callback"`
	// Local configures password policy and lockout rules.
	Local LocalAuthConfig `envPrefix:"AUTH_"`
}

// TTSConfig defines text-to-speech integration settings for ElevenLabs.
type TTSConfig struct {
	// APIKey authenticates requests to the ElevenLabs API. Empty disables TTS.
	APIKey string `env:"API_KEY"`
	// RequestTimeout limits TTS API request duration (default: 60s).
	RequestTimeout time.Duration `env:"TIMEOUT" envDefault:"60s"`
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

	cfg.Database.MigrationsPath = "migrations"

	return &cfg, nil
}

// EnsureDirectories creates all required application directories.
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		c.Audio.ProcessedPath,
		c.Audio.OutputPath,
		c.Audio.TempPath,
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
	if err := c.validateCore(); err != nil {
		return err
	}
	if err := c.validateAuth(); err != nil {
		return err
	}
	if err := c.validateAllowedOrigins(); err != nil {
		return err
	}
	if err := c.validateNotifications(); err != nil {
		return err
	}
	if err := c.validateAudioTools(); err != nil {
		return err
	}
	return nil
}

var guidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validateNotifications permits a completely empty optional configuration,
// but rejects partial or malformed Microsoft Graph settings.
func (c *Config) validateNotifications() error {
	n := &c.Notifications
	g := &n.Email
	if !hasGraphConfiguration(g) {
		return nil
	}
	if err := validateGraphIdentifiers(g); err != nil {
		return err
	}
	if err := validateGraphAddresses(g); err != nil {
		return err
	}
	return validateNotificationPolicy(n)
}

func hasGraphConfiguration(g *GraphConfig) bool {
	values := []string{g.TenantID, g.ClientID, g.ClientSecret, g.FromAddress, g.Recipients}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func validateGraphIdentifiers(g *GraphConfig) error {
	required := []struct {
		name  string
		value string
	}{
		{name: "TENANT_ID", value: g.TenantID},
		{name: "CLIENT_ID", value: g.ClientID},
		{name: "CLIENT_SECRET", value: g.ClientSecret},
		{name: "FROM_ADDRESS", value: g.FromAddress},
		{name: "RECIPIENTS", value: g.Recipients},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_%s is required when e-mail notifications are configured", field.name)
		}
	}
	if !guidPattern.MatchString(g.TenantID) {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_TENANT_ID must be a valid GUID")
	}
	if !guidPattern.MatchString(g.ClientID) {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_CLIENT_ID must be a valid GUID")
	}
	return nil
}

func validateGraphAddresses(g *GraphConfig) error {
	from, err := mail.ParseAddress(g.FromAddress)
	if err != nil {
		return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_FROM_ADDRESS must be a valid e-mail address: %w", err)
	}
	if from.Address != strings.TrimSpace(g.FromAddress) {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_FROM_ADDRESS must contain only the e-mail address")
	}
	recipientCount := 0
	for recipient := range strings.SplitSeq(g.Recipients, ",") {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" {
			continue
		}
		parsed, err := mail.ParseAddress(recipient)
		if err != nil {
			return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS contains an invalid e-mail address: %w", err)
		}
		if parsed.Address != recipient {
			return errors.New("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS must contain only comma-separated e-mail addresses")
		}
		recipientCount++
	}
	if recipientCount == 0 {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS must contain at least one e-mail address")
	}
	return nil
}

func validateNotificationPolicy(n *NotificationConfig) error {
	if n.Cooldown <= 0 {
		return errors.New("BABBEL_NOTIFICATIONS_COOLDOWN must be greater than zero")
	}
	if n.FailureThreshold < 2 {
		return errors.New("BABBEL_NOTIFICATIONS_FAILURE_THRESHOLD must be at least 2")
	}
	if n.FailureWindow <= 0 {
		return errors.New("BABBEL_NOTIFICATIONS_FAILURE_WINDOW must be greater than zero")
	}
	return nil
}

// validateAllowedOrigins ensures each configured CORS/OAuth origin is a bare
// scheme://host[:port] value. Empty configuration is valid (CORS disabled and
// OAuth frontend redirects rejected); malformed entries fail fast at startup
// rather than being silently skipped when matching requests.
func (c *Config) validateAllowedOrigins() error {
	for entry := range strings.SplitSeq(c.Server.AllowedOrigins, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if _, err := normalizeOrigin(entry); err != nil {
			return fmt.Errorf("invalid BABBEL_ALLOWED_ORIGINS entry %q: %w", entry, err)
		}
	}
	return nil
}

func (c *Config) validateCore() error {
	if !c.Auth.Method.IsValid() {
		return fmt.Errorf("invalid auth method: %s (must be local, oidc, or both)", c.Auth.Method)
	}

	if !c.Environment.IsValid() {
		return fmt.Errorf("invalid environment: %s (must be development or production)", c.Environment)
	}

	if c.Database.Port < 1 || c.Database.Port > 65535 {
		return fmt.Errorf("invalid database port: %d (must be 1-65535)", c.Database.Port)
	}

	if err := c.validateDatabasePool(); err != nil {
		return err
	}
	if c.TTS.RequestTimeout <= 0 {
		return fmt.Errorf("BABBEL_ELEVENLABS_TIMEOUT must be > 0 (got %s)", c.TTS.RequestTimeout)
	}
	return nil
}

func (c *Config) validateAuth() error {
	if len(c.Auth.SessionSecret) < 32 {
		return fmt.Errorf("BABBEL_SESSION_SECRET must be at least 32 characters (got %d)", len(c.Auth.SessionSecret))
	}

	if c.Environment == EnvProduction && c.Auth.SessionSecret == "your-secret-key-change-in-production" {
		return errors.New("BABBEL_SESSION_SECRET must be changed from default value in production")
	}

	if c.Auth.Method.SupportsOIDC() {
		if err := c.validateOIDC(); err != nil {
			return err
		}
	}

	if c.Auth.Method.SupportsLocal() {
		if err := c.validateLocalAuth(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) validateOIDC() error {
	if c.Auth.OIDCProviderURL == "" {
		return errors.New("BABBEL_OIDC_PROVIDER_URL required when auth method is 'oidc' or 'both'")
	}
	if c.Auth.OIDCClientID == "" {
		return errors.New("BABBEL_OIDC_CLIENT_ID required when auth method is 'oidc' or 'both'")
	}
	if c.Auth.OIDCClientSecret == "" {
		return errors.New("BABBEL_OIDC_CLIENT_SECRET required when auth method is 'oidc' or 'both'")
	}
	if c.FrontendURL == "" {
		return errors.New("BABBEL_FRONTEND_URL required when auth method is 'oidc' or 'both'")
	}
	return nil
}

func (c *Config) validateAudioTools() error {
	if err := validateAudioTool("FFmpeg", c.Audio.FFmpegPath, "BABBEL_FFMPEG_PATH"); err != nil {
		return err
	}
	if err := validateAudioTool("FFprobe", c.Audio.FFprobePath, "BABBEL_FFPROBE_PATH"); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateDatabasePool() error {
	if c.Database.MaxOpenConns < 1 {
		return fmt.Errorf("BABBEL_DB_MAX_OPEN_CONNS must be >= 1 (got %d)", c.Database.MaxOpenConns)
	}
	if c.Database.MaxIdleConns < 0 {
		return fmt.Errorf("BABBEL_DB_MAX_IDLE_CONNS must be >= 0 (got %d)", c.Database.MaxIdleConns)
	}
	if c.Database.MaxIdleConns > c.Database.MaxOpenConns {
		return fmt.Errorf(
			"BABBEL_DB_MAX_IDLE_CONNS must be <= BABBEL_DB_MAX_OPEN_CONNS (got %d > %d)",
			c.Database.MaxIdleConns,
			c.Database.MaxOpenConns,
		)
	}
	if c.Database.ConnMaxLifetime <= 0 {
		return fmt.Errorf("BABBEL_DB_CONN_MAX_LIFETIME must be > 0 (got %s)", c.Database.ConnMaxLifetime)
	}
	return nil
}

func (c *Config) validateLocalAuth() error {
	if c.Auth.Local.MinPasswordLength < 8 || c.Auth.Local.MinPasswordLength > 128 {
		return errors.New("BABBEL_AUTH_MIN_PASSWORD_LENGTH must be between 8 and 128")
	}
	if c.Auth.Local.MaxLoginAttempts < 1 {
		return fmt.Errorf("BABBEL_AUTH_MAX_LOGIN_ATTEMPTS must be >= 1 (got %d)", c.Auth.Local.MaxLoginAttempts)
	}
	if c.Auth.Local.LockoutDurationMinutes < 1 {
		return fmt.Errorf("BABBEL_AUTH_LOCKOUT_MINUTES must be >= 1 (got %d)", c.Auth.Local.LockoutDurationMinutes)
	}
	return nil
}

func validateAudioTool(name, configuredPath, envVar string) error {
	if configuredPath == "" {
		return fmt.Errorf("%s must not be empty", envVar)
	}

	resolvedPath, err := exec.LookPath(configuredPath)
	if err != nil {
		return fmt.Errorf("%s binary not found at %q: ensure %s points to a valid binary: %w", name, configuredPath, envVar, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), audioToolVersionCheckTimeout)
	defer cancel()

	// #nosec G204 - configured audio tool path with fixed "-version" argument.
	cmd := exec.CommandContext(ctx, resolvedPath, "-version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf(
			"%s binary at %q did not complete -version within %s: ensure %s points to a runnable binary",
			name,
			configuredPath,
			audioToolVersionCheckTimeout,
			envVar,
		)
	}

	outputText := strings.TrimSpace(string(output))
	if outputText != "" {
		return fmt.Errorf(
			"%s binary at %q failed -version check: %s: ensure %s points to a runnable binary: %w",
			name,
			configuredPath,
			outputText,
			envVar,
			err,
		)
	}

	return fmt.Errorf(
		"%s binary at %q failed -version check: ensure %s points to a runnable binary: %w",
		name,
		configuredPath,
		envVar,
		err,
	)
}
