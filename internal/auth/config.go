package auth

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"golang.org/x/oauth2"
)

// Config combines all authentication methods (local, OIDC) and session management settings.
type Config struct {
	// Auth method: "local", "oidc", or "both"
	Method config.AuthMethod

	// OIDC/OAuth2 configuration
	OIDC OIDCConfig

	// Local auth configuration
	Local LocalConfig

	// Session configuration
	Session SessionConfig

	// AllowedOrigins for validating OAuth frontend_url (prevents open redirect)
	AllowedOrigins string
}

// OIDCConfig defines OAuth2/OIDC provider settings for SSO authentication.
type OIDCConfig struct {
	// Provider URL (e.g., https://login.microsoftonline.com/{tenant}/v2.0 for Azure AD)
	ProviderURL string

	// OAuth2 client credentials
	ClientID     string
	ClientSecret string //nolint:gosec // G117: intentional field for auth credentials

	// Redirect URL after authentication
	RedirectURL string

	// OAuth2 scopes
	Scopes []string

	// Optional: specific endpoints (auto-discovered if not set)
	AuthURL  string
	TokenURL string

	// OIDC provider
	Provider *oidc.Provider

	// OAuth2 config
	OAuth2Config *oauth2.Config
}

// LocalConfig defines password policies and lockout rules for database-backed authentication.
type LocalConfig struct {
	// Enable local username/password authentication
	Enabled bool

	// Password policy
	MinPasswordLength      int
	RequireUppercase       bool
	RequireLowercase       bool
	RequireNumbers         bool
	MaxFailedAttempts      int
	LockoutDurationMinutes int
}

// SessionConfig defines how user sessions are stored and secured.
type SessionConfig struct {
	// Session store type: "memory" (default)
	StoreType string

	// Session lifetime
	MaxAge int // seconds

	// Cookie settings
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieSameSite string

	// Secret key for session encryption
	SecretKey string
}
