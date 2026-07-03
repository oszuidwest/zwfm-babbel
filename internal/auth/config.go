package auth

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"golang.org/x/oauth2"
)

// Config combines all authentication methods (local, OIDC) and session management settings.
type Config struct {
	// Method selects the enabled auth method: "local", "oidc", or "both".
	Method config.AuthMethod

	// OIDC contains OAuth2/OIDC provider settings.
	OIDC OIDCConfig

	// Local contains database-backed auth settings.
	Local LocalConfig

	// Session contains session storage and cookie settings.
	Session SessionConfig

	// AllowedOrigins validates OAuth frontend_url values to prevent open redirects.
	AllowedOrigins string
}

// OIDCConfig defines OAuth2/OIDC provider settings for SSO authentication.
type OIDCConfig struct {
	// ProviderURL is the issuer URL, for example https://login.microsoftonline.com/{tenant}/v2.0 for Azure AD.
	ProviderURL string

	// ClientID is the OAuth2 client identifier.
	ClientID string
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string

	// RedirectURL is the OAuth2 callback URL after authentication.
	RedirectURL string

	// Scopes lists the OAuth2 scopes requested during login.
	Scopes []string

	// Provider is the initialized OIDC provider.
	Provider *oidc.Provider

	// OAuth2Config is the initialized OAuth2 client configuration.
	OAuth2Config *oauth2.Config
}

// LocalConfig defines password policies and lockout rules for database-backed authentication.
type LocalConfig struct {
	// Enabled controls local username/password authentication.
	Enabled bool

	// MaxFailedAttempts is the failed-login threshold before lockout.
	MaxFailedAttempts int
	// LockoutDurationMinutes is the account lockout duration after failed attempts.
	LockoutDurationMinutes int
}

// SessionConfig defines how user sessions are stored and secured.
type SessionConfig struct {
	// MaxAge is the session lifetime in seconds.
	MaxAge int

	// CookieName is the browser cookie name.
	CookieName string
	// CookieDomain restricts the session cookie domain.
	CookieDomain string
	// CookiePath restricts the session cookie path.
	CookiePath string
	// CookieSecure restricts the cookie to HTTPS requests.
	CookieSecure bool
	// CookieHTTPOnly prevents JavaScript from reading the session cookie.
	CookieHTTPOnly bool
	// CookieSameSite controls the SameSite cookie attribute.
	CookieSameSite string

	// SecretKey encrypts or signs session data depending on the store.
	SecretKey string
}
