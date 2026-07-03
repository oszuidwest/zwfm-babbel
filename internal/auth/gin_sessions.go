package auth

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// GinSessionStore implements SessionStore using gin-contrib/sessions.
type GinSessionStore struct {
	name string
}

// NewGinSessionStore creates a new server-side in-memory session store.
func NewGinSessionStore(cfg SessionConfig) (SessionStore, sessions.Store, error) {
	store := memstore.NewStore([]byte(cfg.SecretKey))

	// Configure session store options.
	sameSite := config.CookieSameSite(cfg.CookieSameSite)
	store.Options(sessions.Options{
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.MaxAge,
		Secure:   cfg.CookieSecure,
		HttpOnly: cfg.CookieHTTPOnly,
		SameSite: sameSite.ToHTTP(),
	})

	return &GinSessionStore{name: cfg.CookieName}, store, nil
}

// Get returns a session for the given context.
func (s *GinSessionStore) Get(c *gin.Context) Session {
	return &ginSession{
		session: sessions.Default(c),
	}
}

// ginSession implements Session interface.
type ginSession struct {
	session sessions.Session
}

func (s *ginSession) Get(key string) any {
	return s.session.Get(key)
}

func (s *ginSession) Set(key string, value any) {
	s.session.Set(key, value)
}

func (s *ginSession) Delete(key string) {
	s.session.Delete(key)
}

func (s *ginSession) Clear() {
	s.session.Clear()
}

// Save persists the session. The gin.Context parameter is unused here but
// required by the Session interface.
func (s *ginSession) Save(_ *gin.Context) error {
	return s.session.Save()
}
