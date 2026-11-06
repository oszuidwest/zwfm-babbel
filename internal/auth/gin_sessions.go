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
	// Options only sets the cookie attributes. The cookie signature stays valid
	// for 30 days until MaxAge, which the Store interface hides, is called too.
	store.(interface{ MaxAge(int) }).MaxAge(cfg.MaxAge)
	return store
}
