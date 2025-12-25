package config

import "net/http"

// AuthMethod represents the authentication method configuration
type AuthMethod string

const (
	AuthMethodLocal AuthMethod = "local"
	AuthMethodOIDC  AuthMethod = "oidc"
	AuthMethodBoth  AuthMethod = "both"
)

func (a AuthMethod) IsValid() bool {
	switch a {
	case AuthMethodLocal, AuthMethodOIDC, AuthMethodBoth:
		return true
	}
	return false
}

func (a AuthMethod) SupportsLocal() bool {
	return a == AuthMethodLocal || a == AuthMethodBoth
}

func (a AuthMethod) SupportsOIDC() bool {
	return a == AuthMethodOIDC || a == AuthMethodBoth
}

// Environment represents the runtime environment
type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
)

func (e Environment) IsValid() bool {
	switch e {
	case EnvDevelopment, EnvProduction:
		return true
	}
	return false
}

func (e Environment) IsProduction() bool {
	return e == EnvProduction
}

// CookieSameSite represents cookie SameSite policy
type CookieSameSite string

const (
	SameSiteStrict CookieSameSite = "strict"
	SameSiteLax    CookieSameSite = "lax"
	SameSiteNone   CookieSameSite = "none"
)

func (c CookieSameSite) IsValid() bool {
	switch c {
	case SameSiteStrict, SameSiteLax, SameSiteNone:
		return true
	}
	return false
}

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

// SessionStoreType represents the session storage backend
type SessionStoreType string

const (
	StoreTypeMemory SessionStoreType = "memory"
	StoreTypeCookie SessionStoreType = "cookie"
)
