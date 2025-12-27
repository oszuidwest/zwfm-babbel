// Package auth provides authentication and authorization services for the Babbel API.
package auth

import (
	"fmt"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// GinSessionStore implements SessionStore using gin-contrib/sessions
type GinSessionStore struct {
	name string
}

// NewGinSessionStore creates a new session store using gin-contrib/sessions
func NewGinSessionStore(cfg SessionConfig) (SessionStore, sessions.Store, error) {
	var store sessions.Store

	storeType := config.SessionStoreType(cfg.StoreType)
	switch storeType {
	case config.StoreTypeCookie:
		// Cookie-based sessions (encrypted)
		if cfg.SecretKey == "" {
			return nil, nil, fmt.Errorf("secret key is required for cookie store")
		}
		store = cookie.NewStore([]byte(cfg.SecretKey))
	case config.StoreTypeMemory:
		// Memory-based sessions (server-side)
		store = memstore.NewStore([]byte(cfg.SecretKey))
	default:
		// Default to memory store
		store = memstore.NewStore([]byte(cfg.SecretKey))
	}

	// Configure store options
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

func (s *ginSession) Save(_ *gin.Context) error {
	return s.session.Save()
}
