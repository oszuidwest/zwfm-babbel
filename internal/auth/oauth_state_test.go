package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gorillasessions "github.com/gorilla/sessions"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
)

// Both requests load the same old session before either consumes its state.
func TestFinishOAuthFlow_ConcurrentCallbacksConsumeStateOnce(t *testing.T) {
	cfg := &Config{Session: SessionConfig{CookieName: "oauth-state-test", CookiePath: "/", MaxAge: 3600, SecretKey: strings.Repeat("k", 32)}}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), alerts: notify.Discard}
	s.store = &lockedStateStore{Store: s.store, service: s, t: t}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	var requests sync.WaitGroup
	defer func() { cancel(); requests.Wait() }()
	loaded, release, results := make(chan struct{}, 2), make(chan struct{}), make(chan error, 2)
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/start", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(sessKeyOAuthState, "state")
		if err := session.Save(); err != nil {
			t.Error(err)
		}
	})
	router.GET("/callback", func(c *gin.Context) {
		_ = sessions.Default(c).Get(sessKeyOAuthState)
		loaded <- struct{}{}
		select {
		case <-release:
			results <- s.FinishOAuthFlow(c)
		case <-ctx.Done():
			results <- ctx.Err()
		}
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/start", nil))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v, want one session cookie", cookies)
	}
	for range 2 {
		requests.Go(func() {
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/callback?state=state&error=access_denied", nil)
			req.AddCookie(cookies[0])
			router.ServeHTTP(httptest.NewRecorder(), req)
		})
	}
	for range 2 {
		select {
		case <-loaded:
		case <-ctx.Done():
			t.Fatal("callbacks did not both load the session")
		}
	}
	close(release)
	counts := map[string]int{}
	for range 2 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrLoginRejected) {
				t.Fatalf("callback error = %v", err)
			}
			counts[err.Error()]++
		case <-ctx.Done():
			t.Fatal("callbacks did not finish")
		}
	}
	if counts["OIDC login rejected: invalid or expired login state"] != 1 ||
		counts["OIDC login rejected: login was cancelled or denied at the identity provider"] != 1 {
		t.Fatalf("callback results = %v, want one consumed state and one invalid state", counts)
	}
}

// A failed consumption save must stop before touching the OAuth client.
func TestFinishOAuthFlow_StateSaveFailureStopsExchange(t *testing.T) {
	cause := errors.New("session backend unavailable")
	store := &failedStateStore{err: cause}
	s := &Service{config: &Config{Session: SessionConfig{CookieName: "session"}}, store: store, alerts: notify.Discard}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?state=state&code=code", nil)
	err := s.FinishOAuthFlow(c)
	if !errors.Is(err, cause) || errors.Is(err, ErrLoginRejected) || !store.saved {
		t.Fatalf("FinishOAuthFlow = %v, saved = %v; want the session-save failure", err, store.saved)
	}
}

type failedStateStore struct {
	sessions.Store
	err   error
	saved bool
}

func (s *failedStateStore) New(_ *http.Request, name string) (*gorillasessions.Session, error) {
	session := gorillasessions.NewSession(s, name)
	session.Values[sessKeyOAuthState] = "state"
	return session, nil
}

func (s *failedStateStore) Save(*http.Request, http.ResponseWriter, *gorillasessions.Session) error {
	s.saved = true
	return s.err
}

// Assert the lock at the actual write boundary, independently of scheduling.
// The initial fixture save still has its state; consumption deletes it first.
type lockedStateStore struct {
	sessions.Store
	service *Service
	t       *testing.T
}

func (s *lockedStateStore) Save(r *http.Request, w http.ResponseWriter, session *gorillasessions.Session) error {
	if _, hasState := session.Values[sessKeyOAuthState]; !hasState && s.service.oauthStateMu.TryLock() {
		s.service.oauthStateMu.Unlock()
		s.t.Error("OAuth state consumption saved without holding the state lock")
	}
	return s.Store.Save(r, w, session)
}

func TestFinishOAuthFlow_InvalidCookieRejectsLogin(t *testing.T) {
	cfg := &Config{Session: SessionConfig{CookieName: "session", SecretKey: strings.Repeat("k", 32)}}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), alerts: notify.Discard}
	var err error
	router := gin.New()
	router.GET("/callback", s.SessionMiddleware(), func(c *gin.Context) { err = s.FinishOAuthFlow(c) })
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?state=state&code=code", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "corrupt-cookie", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	router.ServeHTTP(httptest.NewRecorder(), req)
	if !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("FinishOAuthFlow = %v, want rejected login", err)
	}
}

// A login that loaded the session before a callback consumed its OAuth state
// must not save that state back.
func TestCreateSessionDropsPendingOAuthState(t *testing.T) {
	cfg := &Config{Session: SessionConfig{CookieName: "session", SecretKey: strings.Repeat("k", 32)}}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), alerts: notify.Discard}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/start", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(sessKeyOAuthState, "state")
		session.Set(sessKeyFrontendURL, "https://app.example.com/")
		_ = session.Save()
	})
	router.GET("/login", func(c *gin.Context) { _ = s.CreateSession(c, 1) })
	var state, frontendURL any
	router.GET("/check", func(c *gin.Context) {
		state, frontendURL = sessions.Default(c).Get(sessKeyOAuthState), sessions.Default(c).Get(sessKeyFrontendURL)
	})
	start := httptest.NewRecorder()
	router.ServeHTTP(start, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/start", nil))
	for _, path := range []string{"/login", "/check"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		for _, cookie := range start.Result().Cookies() {
			req.AddCookie(cookie)
		}
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	if state != nil || frontendURL != nil {
		t.Fatalf("session after login: state = %v, frontend URL = %v; want both removed", state, frontendURL)
	}
}

// Session cleanup must not save back a state that a callback consumed after
// this request loaded its session.
func TestClearSessionUserKeepsConsumedState(t *testing.T) {
	cfg := &Config{Session: SessionConfig{CookieName: "session", SecretKey: strings.Repeat("k", 32)}}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), alerts: notify.Discard}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/start", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(sessKeyUserID, int64(1))
		session.Set(sessKeyOAuthState, "consumed")
		_ = session.Save()
	})
	router.GET("/cleanup", func(c *gin.Context) {
		_ = sessions.Default(c).Get(sessKeyUserID) // This request's snapshot.
		consumed, _ := s.store.New(c.Request, cfg.Session.CookieName)
		delete(consumed.Values, sessKeyOAuthState)
		if err := s.store.Save(c.Request, httptest.NewRecorder(), consumed); err != nil {
			t.Error(err)
		}
		if err := s.clearSessionUser(c); err != nil {
			t.Error(err)
		}
	})
	var userID, state any
	router.GET("/check", func(c *gin.Context) {
		userID, state = sessions.Default(c).Get(sessKeyUserID), sessions.Default(c).Get(sessKeyOAuthState)
	})
	start := httptest.NewRecorder()
	router.ServeHTTP(start, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/start", nil))
	for _, path := range []string{"/cleanup", "/check"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		for _, cookie := range start.Result().Cookies() {
			req.AddCookie(cookie)
		}
		router.ServeHTTP(httptest.NewRecorder(), req)
	}
	if userID != nil || state != nil {
		t.Fatalf("session after cleanup: user = %v, state = %v; want both gone", userID, state)
	}
}
