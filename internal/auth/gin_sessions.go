package auth

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
)

// GinSessionStore implements SessionStore using gin-contrib/sessions
type GinSessionStore struct {
	name string
}

// NewGinSessionStore creates a new session store using gin-contrib/sessions
func NewGinSessionStore(cfg SessionConfig) (SessionStore, sessions.Store, error) {
	var store sessions.Store

	switch cfg.StoreType {
	case "cookie":
		// Cookie-based sessions (encrypted)
		if cfg.SecretKey == "" {
			return nil, nil, fmt.Errorf("secret key is required for cookie store")
		}
		store = cookie.NewStore([]byte(cfg.SecretKey))
	case "memory":
		// Memory-based sessions (server-side)
		store = memstore.NewStore([]byte(cfg.SecretKey))
	default:
		// Default to memory store
		store = memstore.NewStore([]byte(cfg.SecretKey))
	}

	// Configure store options
	store.Options(sessions.Options{
		Path:     cfg.CookiePath,
		Domain:   cfg.CookieDomain,
		MaxAge:   cfg.MaxAge,
		Secure:   cfg.CookieSecure,
		HttpOnly: cfg.CookieHTTPOnly,
		SameSite: parseSameSite(cfg.CookieSameSite),
	})

	return &GinSessionStore{name: cfg.CookieName}, store, nil
}

func parseSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		return http.SameSiteLaxMode
	default:
		return http.SameSiteDefaultMode
	}
}

// Get returns a session for the given context
func (s *GinSessionStore) Get(c *gin.Context) Session {
	return &ginSession{
		session: sessions.Default(c),
		ctx:     c,
	}
}

// ginSession implements Session interface
type ginSession struct {
	session sessions.Session
	ctx     *gin.Context
}

func (s *ginSession) Get(key string) interface{} {
	return s.session.Get(key)
}

func (s *ginSession) Set(key string, value interface{}) {
	s.session.Set(key, value)
}

func (s *ginSession) Delete(key string) {
	s.session.Delete(key)
}

func (s *ginSession) Clear() {
	s.session.Clear()
}

func (s *ginSession) Save(_ *gin.Context) error {
	return s.session.Save()
}

// CreateSessionMiddleware creates a session middleware for gin-contrib/sessions.
func CreateSessionMiddleware(name string, store sessions.Store) gin.HandlerFunc {
	return sessions.Sessions(name, store)
}
