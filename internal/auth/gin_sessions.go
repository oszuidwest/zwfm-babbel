package auth

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// newSessionStore creates a server-side in-memory session store.
func newSessionStore(cfg SessionConfig) sessions.Store {
	store := memstore.NewStore([]byte(cfg.SecretKey))
	store.Options(sessions.Options{
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.MaxAge,
		Secure:   cfg.CookieSecure,
		HttpOnly: cfg.CookieHTTPOnly,
		SameSite: config.CookieSameSite(cfg.CookieSameSite).ToHTTP(),
	})
	return store
}
