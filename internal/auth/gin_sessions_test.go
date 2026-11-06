package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// sessionFixture runs the real store. do requests /login or /oauth with cookies
// and returns the cookies it sets; loggedIn reports whether cookies hold a login.
func sessionFixture(t *testing.T) (do func(path string, cookies []*http.Cookie) []*http.Cookie, loggedIn func(cookies []*http.Cookie) bool) {
	t.Helper()
	cfg := &Config{Method: config.AuthMethodOIDC, Session: SessionConfig{CookieName: "session", MaxAge: 86400}}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), oauth: &oauth2.Config{}}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/login", func(c *gin.Context) {
		if err := s.CreateSession(c, 1); err != nil {
			t.Error(err)
		}
	})
	router.GET("/oauth", s.StartOAuthFlow)
	var user any
	router.GET("/user", func(c *gin.Context) { user = sessions.Default(c).Get(sessKeyUserID) })
	do = func(path string, cookies []*http.Cookie) []*http.Cookie {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Result().Cookies()
	}
	return do, func(cookies []*http.Cookie) bool {
		do("/user", cookies)
		return user != nil
	}
}

// A copied cookie must stop working at MaxAge, as the browser's copy does.
func TestSessionCookieExpiresAtMaxAge(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		do, loggedIn := sessionFixture(t)
		cookies := do("/login", nil)
		time.Sleep(24 * time.Hour)
		if !loggedIn(cookies) {
			t.Fatal("session rejected at MaxAge, want accepted")
		}
		time.Sleep(time.Second)
		if loggedIn(cookies) {
			t.Fatal("session accepted after MaxAge")
		}
	})
}

// A restart means a new store with a new key. The old cookie must then read as
// anonymous, and the client must be able to log in again.
func TestSessionCookieFromBeforeRestart(t *testing.T) {
	login, _ := sessionFixture(t)
	stale := login("/login", nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.AddCookie(stale[0])
	if _, err := newSessionStore(SessionConfig{}).New(req, "session"); err == nil {
		t.Fatal("new store accepted the old signature, want a new key per store")
	}

	do, loggedIn := sessionFixture(t)
	if loggedIn(stale) {
		t.Fatal("cookie from before the restart is logged in")
	}
	if !loggedIn(do("/login", stale)) {
		t.Fatal("login with a stale cookie did not save a new session")
	}
}

// Starting an OAuth flow writes a fresh cookie, which must not extend a login.
func TestStartOAuthFlowDoesNotKeepLogin(t *testing.T) {
	do, loggedIn := sessionFixture(t)
	if refreshed := do("/oauth", do("/login", nil)); loggedIn(refreshed) {
		t.Fatal("cookie from StartOAuthFlow is still logged in")
	}
}
