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
