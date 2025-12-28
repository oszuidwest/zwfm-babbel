package config

import "net/http"

// AuthMethod represents the authentication method configuration.
type AuthMethod string

// Authentication methods supported by the application.
const (
	// AuthMethodLocal enables username/password authentication
	AuthMethodLocal AuthMethod = "local"
	// AuthMethodOIDC enables OAuth/OIDC authentication
	AuthMethodOIDC AuthMethod = "oidc"
	// AuthMethodBoth enables both local and OIDC authentication
	AuthMethodBoth AuthMethod = "both"
)

// IsValid reports whether the authentication method is recognized.
func (a AuthMethod) IsValid() bool {
	switch a {
	case AuthMethodLocal, AuthMethodOIDC, AuthMethodBoth:
		return true
	}
	return false
}

// SupportsLocal reports whether local authentication is enabled.
func (a AuthMethod) SupportsLocal() bool {
	return a == AuthMethodLocal || a == AuthMethodBoth
}

// SupportsOIDC reports whether OAuth/OIDC authentication is enabled.
func (a AuthMethod) SupportsOIDC() bool {
	return a == AuthMethodOIDC || a == AuthMethodBoth
}

// Environment represents the runtime environment.
type Environment string

// Runtime environments supported by the application.
const (
	// EnvDevelopment represents the development environment.
	EnvDevelopment Environment = "development"
	// EnvProduction represents the production environment.
	EnvProduction Environment = "production"
)

// IsValid reports whether the environment is recognized.
func (e Environment) IsValid() bool {
	switch e {
	case EnvDevelopment, EnvProduction:
		return true
	}
	return false
}

// IsProduction reports whether the environment is production.
func (e Environment) IsProduction() bool {
	return e == EnvProduction
}

// CookieSameSite represents cookie SameSite policy.
type CookieSameSite string

// Cookie SameSite policies supported by the application.
const (
	// SameSiteStrict restricts cookies to same-site requests only.
	SameSiteStrict CookieSameSite = "strict"
	// SameSiteLax allows cookies on top-level navigation (default).
	SameSiteLax CookieSameSite = "lax"
	// SameSiteNone allows cookies on cross-site requests (requires HTTPS).
	SameSiteNone CookieSameSite = "none"
)

// IsValid reports whether the SameSite policy is recognized.
func (c CookieSameSite) IsValid() bool {
	switch c {
	case SameSiteStrict, SameSiteLax, SameSiteNone:
		return true
	}
	return false
}

// ToHTTP converts the SameSite policy to the http.SameSite type.
func (c CookieSameSite) ToHTTP() http.SameSite {
	switch c {
	case SameSiteStrict:
		return http.SameSiteStrictMode
	case SameSiteNone:
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// SessionStoreType represents the session storage backend.
type SessionStoreType string

// Session storage backends supported by the application.
const (
	// StoreTypeMemory stores sessions in memory (not suitable for production).
	StoreTypeMemory SessionStoreType = "memory"
	// StoreTypeCookie stores sessions in encrypted cookies.
	StoreTypeCookie SessionStoreType = "cookie"
)
