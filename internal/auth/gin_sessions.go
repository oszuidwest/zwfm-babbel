package auth

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// Session is the request session. Key types match gin-contrib/sessions. Save
// takes the gin.Context for callers' convenience; the request's session is
// already bound to it.
type Session interface {
	Get(key any) any
	Set(key, value any)
	Delete(key any)
	Clear()
	Save(c *gin.Context) error
}

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

// ginSession adapts gin-contrib's session to Session.
type ginSession struct{ sessions.Session }

func (s ginSession) Save(*gin.Context) error { return s.Session.Save() }

func sessionFor(c *gin.Context) Session { return ginSession{sessions.Default(c)} }
