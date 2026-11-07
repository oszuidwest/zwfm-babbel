package auth

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	gorillasessions "github.com/gorilla/sessions"
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

// A long query around a short frontend_url must not stay in memory with the session.
func TestStartOAuthFlowKeepsOnlyTheFrontendURL(t *testing.T) {
	cfg := &Config{
		Method: config.AuthMethodOIDC, AllowedOrigins: "https://app.example",
		Session: SessionConfig{CookieName: "session", MaxAge: 86400},
	}
	s := &Service{config: cfg, store: newSessionStore(cfg.Session), oauth: &oauth2.Config{}}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/oauth", s.StartOAuthFlow)
	target := "/oauth?frontend_url=https://app.example/&pad=" + strings.Repeat("x", 1<<20)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 20 {
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if after.HeapAlloc > before.HeapAlloc+5<<20 {
		t.Fatalf("heap grew from %d to %d bytes after 20 login starts with a 1 MiB query", before.HeapAlloc, after.HeapAlloc)
	}
	runtime.KeepAlive(s)
}

// storeFixture runs the real store without a router. save stores values under
// the cookie's session, or a new one, and returns its cookie; load reads the
// cookie's session.
func storeFixture(t *testing.T) (store sessions.Store, save func(*http.Cookie, map[any]any) *http.Cookie, load func(*http.Cookie) *gorillasessions.Session) {
	t.Helper()
	store = newSessionStore(SessionConfig{MaxAge: 3600})
	request := func(cookie *http.Cookie) *http.Request {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		return req
	}
	load = func(cookie *http.Cookie) *gorillasessions.Session {
		session, err := store.New(request(cookie), "session")
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	save = func(cookie *http.Cookie, values map[any]any) *http.Cookie {
		session := load(cookie)
		session.Values = values
		rec := httptest.NewRecorder()
		if err := store.Save(request(cookie), rec, session); err != nil {
			t.Fatal(err)
		}
		return rec.Result().Cookies()[0]
	}
	return store, save, load
}

// A flood of login starts pushes out the oldest start, not a session with a user.
func TestSessionStoreCapDropsOldestWithoutUser(t *testing.T) {
	_, save, load := storeFixture(t)
	pending := map[any]any{sessKeyOAuthState: "state"}
	user := save(nil, map[any]any{sessKeyUserID: int64(1)})
	oldest := save(nil, pending)
	next := save(nil, pending)
	for range maxSessions - 3 {
		save(nil, pending)
	}
	if load(oldest).IsNew {
		t.Fatal("oldest start dropped at the cap, want dropped above it")
	}
	save(nil, pending)
	if !load(oldest).IsNew || load(next).IsNew || load(user).IsNew {
		t.Fatalf("above the cap: oldest gone = %v, next gone = %v, user gone = %v; want only oldest gone",
			load(oldest).IsNew, load(next).IsNew, load(user).IsNew)
	}
}

// Entries end at MaxAge counted from their last save.
func TestSessionStoreRemovesExpiredEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store, save, load := storeFixture(t)
		renewed := save(nil, map[any]any{})
		save(nil, map[any]any{})
		time.Sleep(30 * time.Minute)
		renewed = save(renewed, map[any]any{})
		time.Sleep(30*time.Minute + time.Second)
		save(nil, map[any]any{})
		if got := len(store.(*memoryStore).entries); got != 2 || load(renewed).IsNew {
			t.Fatalf("entries = %d, renewed gone = %v; want 2 and false", got, load(renewed).IsNew)
		}
	})
}

// Only Save changes the store: neither the caller's map nor a loaded copy is
// the stored one.
func TestSessionStoreCopiesValues(t *testing.T) {
	_, save, load := storeFixture(t)
	values := map[any]any{sessKeyOAuthState: "state"}
	cookie := save(nil, values)
	values[sessKeyOAuthState] = "changed after save"
	if got := load(cookie).Values[sessKeyOAuthState]; got != "state" {
		t.Fatalf("after changing the saved map: state = %v", got)
	}
	load(cookie).Values[sessKeyOAuthState] = "changed without save"
	if got := load(cookie).Values[sessKeyOAuthState]; got != "state" {
		t.Fatalf("after changing a loaded copy: state = %v", got)
	}
}
