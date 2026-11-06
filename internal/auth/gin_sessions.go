package auth

import (
	"crypto/rand"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// newSessionStore creates a server-side in-memory session store. Its key only
// signs the session ID. A restart ends every session anyway, so each store gets
// a new random key. rand.Read crashes the program if it cannot read, so there
// is no error to handle and no weak key to fall back to.
func newSessionStore(cfg SessionConfig) sessions.Store {
	key := make([]byte, 32)
	rand.Read(key)
	store := memstore.NewStore(key)
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
