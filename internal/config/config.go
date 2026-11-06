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

const (
	// generationTimeout bounds one bulletin generation, for automation
	// requests and for asynchronous jobs.
	generationTimeout = 120 * time.Second
	ttsRequestTimeout = 60 * time.Second
)

// Config is the environment-backed runtime configuration.
type Config struct {
	Server        ServerConfig
	Database      DatabaseConfig `envPrefix:"DB_"`
	Auth          AuthConfig
	Audio         AudioConfig
	Automation    AutomationConfig
	BulletinJobs  BulletinJobConfig
	TTS           TTSConfig          `envPrefix:"ELEVENLABS_"`
	Notifications NotificationConfig `envPrefix:"NOTIFICATIONS_"`
	// LogLevel values of 5 or higher enable debug logging; lower values log at info.
	LogLevel int `env:"LOG_LEVEL" envDefault:"4"`
	// Environment accepts development or production.
	Environment Environment `env:"ENV" envDefault:"production"`
	// FrontendURL is the OAuth post-login redirect base.
	FrontendURL string `env:"FRONTEND_URL"`
}

// NotificationConfig defines alert delivery and duplicate-suppression policy.
type NotificationConfig struct {
	Email GraphConfig `envPrefix:"EMAIL_"`
	// Cooldown suppresses repeats for an active alert key.
	Cooldown time.Duration
	// FailureThreshold failures within FailureWindow trigger an alert.
	FailureThreshold int
	FailureWindow    time.Duration
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
	Key               string `env:"AUTOMATION_KEY"`
	GenerationTimeout time.Duration
}

// BulletinJobConfig defines asynchronous bulletin worker settings.
type BulletinJobConfig struct {
	// GenerationTimeout applies to one generation attempt.
	GenerationTimeout time.Duration
}

// ServerConfig defines HTTP server and CORS settings.
type ServerConfig struct {
	// AllowedOrigins is a comma-separated CORS allowlist.
	AllowedOrigins string `env:"ALLOWED_ORIGINS"`
}

// DatabaseConfig defines MySQL database connection parameters.
type DatabaseConfig struct {
	// Host is host or host:port. The driver adds port 3306 when none is given.
	Host            string `env:"HOST" envDefault:"localhost"`
	User            string `env:"USER" envDefault:"babbel"`
	Password        string `env:"PASSWORD"`
	Database        string `env:"NAME" envDefault:"babbel"`
	MaxOpenConns    int    `env:"MAX_OPEN_CONNS" envDefault:"100"`
	ConnMaxLifetime time.Duration
	ConnectTimeout  time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// MaxPasswordBytes is the longest password bcrypt accepts.
const MaxPasswordBytes = 72

// LocalAuthConfig defines password policy and lockout rules for local authentication.
type LocalAuthConfig struct {
	// MinPasswordLength must be between 8 and 72, the bcrypt byte limit.
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
	Method       AuthMethod `env:"AUTH_METHOD" envDefault:"local"`
	CookieDomain string     `env:"COOKIE_DOMAIN"`
	// CookieSameSite accepts strict, lax, or none.
	CookieSameSite   CookieSameSite  `env:"COOKIE_SAMESITE" envDefault:"lax"`
	OIDCProviderURL  string          `env:"OIDC_PROVIDER_URL"`
	OIDCClientID     string          `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string          `env:"OIDC_CLIENT_SECRET"`
	OIDCRedirectURL  string          `env:"OIDC_REDIRECT_URL"`
	Local            LocalAuthConfig `envPrefix:"AUTH_"`
}

// TTSConfig defines text-to-speech integration settings for ElevenLabs.
type TTSConfig struct {
	// APIKey authenticates requests to the ElevenLabs API. Empty disables TTS.
	APIKey         string `env:"API_KEY"`
	RequestTimeout time.Duration
}

// AudioConfig defines audio processing and file storage settings.
type AudioConfig struct {
	FFmpegPath    string
	FFprobePath   string
	ProcessedPath string
	OutputPath    string
	// TempPath owns upload/TTS inputs; cleanup removes old regular files here.
	TempPath string
	// BulletinRetention controls when bulletin audio files and finished job
	// records are purged; bulletin records remain as the audit trail.
	BulletinRetention time.Duration `env:"BULLETIN_RETENTION" envDefault:"168h"`
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := fixedConfig()
	if err := env.ParseWithOptions(&cfg, env.Options{Prefix: "BABBEL_"}); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &cfg, nil
}

// fixedConfig returns the settings that are code constants instead of
// environment variables. Tests can still set these fields directly.
func fixedConfig() Config {
	return Config{
		Audio: AudioConfig{
			FFmpegPath:    "ffmpeg",
			FFprobePath:   "ffprobe",
			ProcessedPath: "./audio/processed",
			OutputPath:    "./audio/output",
			TempPath:      "./audio/temp",
		},
		Automation:   AutomationConfig{GenerationTimeout: generationTimeout},
		BulletinJobs: BulletinJobConfig{GenerationTimeout: generationTimeout},
		TTS:          TTSConfig{RequestTimeout: ttsRequestTimeout},
		Database: DatabaseConfig{
			ConnMaxLifetime: time.Hour,
			// Transport deadlines also bound queries and COMMIT when the peer
			// stops answering. Read and write allow long maintenance queries.
			ConnectTimeout: 10 * time.Second,
			ReadTimeout:    2 * time.Minute,
			WriteTimeout:   2 * time.Minute,
		},
		Notifications: NotificationConfig{
			Cooldown:         time.Hour,
			FailureThreshold: 3,
			FailureWindow:    10 * time.Minute,
		},
	}
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
	g := &c.Notifications.Email
	if !hasGraphConfiguration(g) {
		return nil
	}
	if err := validateGraphIdentifiers(g); err != nil {
		return err
	}
	return validateGraphAddresses(g)
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

	if c.Database.MaxOpenConns < 1 {
		return fmt.Errorf("BABBEL_DB_MAX_OPEN_CONNS must be >= 1 (got %d)", c.Database.MaxOpenConns)
	}

	if c.Database.Password == "" {
		return errors.New("BABBEL_DB_PASSWORD is required")
	}

	// A zero retention would purge all bulletin audio at the next cleanup,
	// except the newest bulletin per station.
	if c.Audio.BulletinRetention <= 0 {
		return fmt.Errorf("BABBEL_BULLETIN_RETENTION must be > 0 (got %s)", c.Audio.BulletinRetention)
	}
	return nil
}

func (c *Config) validateAuth() error {
	if !c.Auth.CookieSameSite.IsValid() {
		return fmt.Errorf("invalid BABBEL_COOKIE_SAMESITE: %s (must be strict, lax, or none)", c.Auth.CookieSameSite)
	}

	if c.Auth.Local.MinPasswordLength < 8 || c.Auth.Local.MinPasswordLength > MaxPasswordBytes {
		return fmt.Errorf("BABBEL_AUTH_MIN_PASSWORD_LENGTH must be between 8 and %d", MaxPasswordBytes)
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
	if c.Auth.OIDCRedirectURL == "" {
		return errors.New("BABBEL_OIDC_REDIRECT_URL required when auth method is 'oidc' or 'both'")
	}
	if c.FrontendURL == "" {
		return errors.New("BABBEL_FRONTEND_URL required when auth method is 'oidc' or 'both'")
	}
	return nil
}

func (c *Config) validateAudioTools() error {
	if err := validateAudioTool("FFmpeg", c.Audio.FFmpegPath); err != nil {
		return err
	}
	if err := validateAudioTool("FFprobe", c.Audio.FFprobePath); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateLocalAuth() error {
	if c.Auth.Local.MaxLoginAttempts < 1 {
		return fmt.Errorf("BABBEL_AUTH_MAX_LOGIN_ATTEMPTS must be >= 1 (got %d)", c.Auth.Local.MaxLoginAttempts)
	}
	if c.Auth.Local.LockoutDurationMinutes < 1 {
		return fmt.Errorf("BABBEL_AUTH_LOCKOUT_MINUTES must be >= 1 (got %d)", c.Auth.Local.LockoutDurationMinutes)
	}
	return nil
}

func validateAudioTool(name, configuredPath string) error {
	resolvedPath, err := exec.LookPath(configuredPath)
	if err != nil {
		return fmt.Errorf("%s binary not found at %q: install the tool or fix PATH: %w", name, configuredPath, err)
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
			"%s binary at %q did not complete -version within %s: install the tool or fix PATH",
			name,
			configuredPath,
			audioToolVersionCheckTimeout,
		)
	}

	outputText := strings.TrimSpace(string(output))
	if outputText != "" {
		return fmt.Errorf(
			"%s binary at %q failed -version check: %s: install the tool or fix PATH: %w",
			name,
			configuredPath,
			outputText,
			err,
		)
	}

	return fmt.Errorf(
		"%s binary at %q failed -version check: install the tool or fix PATH: %w",
		name,
		configuredPath,
		err,
	)
}
