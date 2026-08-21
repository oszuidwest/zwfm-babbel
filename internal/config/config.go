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
	Server        ServerConfig
	Database      DatabaseConfig `envPrefix:"DB_"`
	Auth          AuthConfig
	Audio         AudioConfig
	Automation    AutomationConfig
	BulletinJobs  BulletinJobConfig  `envPrefix:"BULLETIN_JOBS_"`
	TTS           TTSConfig          `envPrefix:"ELEVENLABS_"`
	Notifications NotificationConfig `envPrefix:"NOTIFICATIONS_"`
	// LogLevel ranges from 0 (silent) to 5 (trace).
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment accepts development or production.
	Environment Environment `env:"ENV" envDefault:"development"`
	// FrontendURL is the OAuth post-login redirect base.
	FrontendURL string `env:"FRONTEND_URL"`
}

// NotificationConfig defines alert delivery and duplicate-suppression policy.
type NotificationConfig struct {
	Email GraphConfig `envPrefix:"EMAIL_"`
	// Cooldown suppresses repeats for an active alert key.
	Cooldown time.Duration `env:"COOLDOWN" envDefault:"1h"`
	// FailureThreshold failures within FailureWindow trigger an alert.
	FailureThreshold int           `env:"FAILURE_THRESHOLD" envDefault:"3"`
	FailureWindow    time.Duration `env:"FAILURE_WINDOW" envDefault:"10m"`
}

// GraphConfig defines Microsoft Graph client-credentials mail settings.
type GraphConfig struct {
	TenantID     string `env:"TENANT_ID"`
	ClientID     string `env:"CLIENT_ID"`
	ClientSecret string `env:"CLIENT_SECRET"`
	FromAddress  string `env:"FROM_ADDRESS"`
	// Recipients is a comma-separated address list.
	Recipients string `env:"RECIPIENTS"`
}

// RecipientList returns the trimmed, non-empty recipient addresses.
func (g *GraphConfig) RecipientList() []string {
	var recipients []string
	for recipient := range strings.SplitSeq(g.Recipients, ",") {
		if recipient = strings.TrimSpace(recipient); recipient != "" {
			recipients = append(recipients, recipient)
		}
	}
	return recipients
}

// requiredSettings pairs each Graph environment variable name with its value.
// It is the single list behind IsComplete, hasGraphConfiguration, and validation.
func (g *GraphConfig) requiredSettings() []struct{ name, value string } {
	return []struct{ name, value string }{
		{name: "TENANT_ID", value: g.TenantID},
		{name: "CLIENT_ID", value: g.ClientID},
		{name: "CLIENT_SECRET", value: g.ClientSecret},
		{name: "FROM_ADDRESS", value: g.FromAddress},
		{name: "RECIPIENTS", value: g.Recipients},
	}
}

// IsComplete reports whether every Microsoft Graph delivery setting is present.
func (g *GraphConfig) IsComplete() bool {
	for _, setting := range g.requiredSettings() {
		if strings.TrimSpace(setting.value) == "" {
			return false
		}
	}
	return len(g.RecipientList()) > 0
}

// AutomationConfig defines settings for radio automation system integration.
type AutomationConfig struct {
	// Key authenticates automation system requests. Empty disables the endpoint.
	Key               string        `env:"AUTOMATION_KEY"`
	GenerationTimeout time.Duration `env:"AUTOMATION_TIMEOUT" envDefault:"120s"`
}

// BulletinJobConfig defines asynchronous bulletin worker settings.
type BulletinJobConfig struct {
	// GenerationTimeout applies to one worker attempt.
	GenerationTimeout time.Duration `env:"GENERATION_TIMEOUT" envDefault:"120s"`
	// QueueTimeout bounds how long an unclaimed job may wait.
	QueueTimeout time.Duration `env:"QUEUE_TIMEOUT" envDefault:"15m"`
	// Workers limits cross-station generation concurrency.
	Workers int `env:"WORKERS" envDefault:"4"`
}

// ServerConfig defines HTTP server and CORS settings.
type ServerConfig struct {
	Address string `env:"SERVER_ADDRESS" envDefault:":8080"`
	// AllowedOrigins is a comma-separated CORS allowlist.
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`
}

// DatabaseConfig defines MySQL database connection parameters.
type DatabaseConfig struct {
	Host            string        `env:"HOST" envDefault:"localhost"`
	Port            int           `env:"PORT" envDefault:"3306"`
	User            string        `env:"USER" envDefault:"babbel"`
	Password        string        `env:"PASSWORD" envDefault:"babbel"`
	Database        string        `env:"NAME" envDefault:"babbel"`
	MigrationsPath  string        `env:"-"`
	MaxOpenConns    int           `env:"MAX_OPEN_CONNS" envDefault:"100"`
	MaxIdleConns    int           `env:"MAX_IDLE_CONNS" envDefault:"10"`
	ConnMaxLifetime time.Duration `env:"CONN_MAX_LIFETIME" envDefault:"1h"`
}

// LocalAuthConfig defines password policy and lockout rules for local authentication.
type LocalAuthConfig struct {
	// MinPasswordLength must be between 8 and 128.
	MinPasswordLength      int  `env:"MIN_PASSWORD_LENGTH" envDefault:"8"`
	RequireUppercase       bool `env:"REQUIRE_UPPERCASE" envDefault:"true"`
	RequireLowercase       bool `env:"REQUIRE_LOWERCASE" envDefault:"true"`
	RequireNumber          bool `env:"REQUIRE_NUMBER" envDefault:"true"`
	RequireSpecialChar     bool `env:"REQUIRE_SPECIAL" envDefault:"false"`
	MaxLoginAttempts       int  `env:"MAX_LOGIN_ATTEMPTS" envDefault:"5"`
	LockoutDurationMinutes int  `env:"LOCKOUT_MINUTES" envDefault:"15"`
}

// AuthConfig defines authentication and session settings.
type AuthConfig struct {
	Method AuthMethod `env:"AUTH_METHOD" envDefault:"local"`
	// SessionSecret provides the key for session encryption (min 32 characters).
	SessionSecret string `env:"SESSION_SECRET" envDefault:"your-secret-key-change-in-production"`
	CookieDomain  string `env:"COOKIE_DOMAIN"`
	// CookieSameSite accepts strict, lax, or none.
	CookieSameSite   CookieSameSite  `env:"COOKIE_SAMESITE" envDefault:"lax"`
	OIDCProviderURL  string          `env:"OIDC_PROVIDER_URL"`
	OIDCClientID     string          `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string          `env:"OIDC_CLIENT_SECRET"`
	OIDCRedirectURL  string          `env:"OIDC_REDIRECT_URL" envDefault:"http://localhost:8080/api/v1/auth/oauth/callback"`
	Local            LocalAuthConfig `envPrefix:"AUTH_"`
}

// TTSConfig defines text-to-speech integration settings for ElevenLabs.
type TTSConfig struct {
	// APIKey authenticates requests to the ElevenLabs API. Empty disables TTS.
	APIKey         string        `env:"API_KEY"`
	RequestTimeout time.Duration `env:"TIMEOUT" envDefault:"60s"`
}

// AudioConfig defines audio processing and file storage settings.
type AudioConfig struct {
	FFmpegPath    string `env:"FFMPEG_PATH" envDefault:"ffmpeg"`
	FFprobePath   string `env:"FFPROBE_PATH" envDefault:"ffprobe"`
	ProcessedPath string `env:"PROCESSED_PATH" envDefault:"./audio/processed"`
	OutputPath    string `env:"OUTPUT_PATH" envDefault:"./audio/output"`
	TempPath      string `env:"TEMP_PATH" envDefault:"./audio/temp"`
	// AppRoot resolves application-relative assets.
	AppRoot string `env:"APP_ROOT" envDefault:"/app"`
	// BulletinRetention controls when audio files, not records, are purged.
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

// hasGraphConfiguration reports whether any required Graph setting is present.
func hasGraphConfiguration(g *GraphConfig) bool {
	for _, setting := range g.requiredSettings() {
		if strings.TrimSpace(setting.value) != "" {
			return true
		}
	}
	return false
}

// validateGraphIdentifiers requires all Graph settings and validates GUIDs.
func validateGraphIdentifiers(g *GraphConfig) error {
	for _, setting := range g.requiredSettings() {
		if strings.TrimSpace(setting.value) == "" {
			return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_%s is required when e-mail notifications are configured", setting.name)
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

// validateGraphAddresses validates the sender and recipient mailbox addresses.
func validateGraphAddresses(g *GraphConfig) error {
	from, err := mail.ParseAddress(g.FromAddress)
	if err != nil {
		return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_FROM_ADDRESS must be a valid e-mail address: %w", err)
	}
	if from.Address != strings.TrimSpace(g.FromAddress) {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_FROM_ADDRESS must contain only the e-mail address")
	}
	recipients := g.RecipientList()
	if len(recipients) == 0 {
		return errors.New("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS must contain at least one e-mail address")
	}
	for _, recipient := range recipients {
		parsed, err := mail.ParseAddress(recipient)
		if err != nil {
			return fmt.Errorf("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS contains an invalid e-mail address: %w", err)
		}
		if parsed.Address != recipient {
			return errors.New("BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS must contain only comma-separated e-mail addresses")
		}
	}
	return nil
}

// validateNotificationPolicy checks threshold, window, and cooldown bounds.
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
	if c.BulletinJobs.GenerationTimeout <= 0 {
		return fmt.Errorf("BABBEL_BULLETIN_JOBS_GENERATION_TIMEOUT must be > 0 (got %s)", c.BulletinJobs.GenerationTimeout)
	}
	if c.BulletinJobs.QueueTimeout <= 0 {
		return fmt.Errorf("BABBEL_BULLETIN_JOBS_QUEUE_TIMEOUT must be > 0 (got %s)", c.BulletinJobs.QueueTimeout)
	}
	if c.BulletinJobs.Workers < 1 {
		return fmt.Errorf("BABBEL_BULLETIN_JOBS_WORKERS must be >= 1 (got %d)", c.BulletinJobs.Workers)
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
