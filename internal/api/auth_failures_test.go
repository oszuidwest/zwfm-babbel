package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestGetCurrentUserLogsPermissionCause(t *testing.T) {
	cause := errors.New("evaluate stories/read permission: evaluator unavailable")
	h := &AuthHandlers{permissions: func(string) (auth.PermissionSet, error) { return nil, cause }}
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/sessions/current", nil)
	auth.SetUserContext(c, auth.UserContext{UserID: 7, Role: "viewer"})
	h.GetCurrentUser(c)
	var record map[string]any
	if rec.Code != http.StatusInternalServerError || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" ||
		record["role"] != "viewer" || record["error"] != cause.Error() {
		t.Fatalf("status = %d, logs = %s", rec.Code, logs)
	}
}

func TestOAuthCallbackWhenOAuthDisabled(t *testing.T) {
	s, err := auth.NewService(&auth.Config{Method: config.AuthMethodLocal, Session: auth.SessionConfig{CookieName: "session"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/callback", NewAuthHandlers(s, testFrontendURL, nil).HandleOAuthCallback)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "OAuth authentication is disabled") {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

// Logout needs only the session, so it works while the database is down. A
// session without a user still gets 401.
func TestLogoutWhileDatabaseDown(t *testing.T) {
	db, err := gorm.Open(mysql.New(mysql.Config{DSN: "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel", SkipInitializeWithVersion: true}),
		&gorm.Config{DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	s, err := auth.NewService(&auth.Config{Method: config.AuthMethodLocal, Session: auth.SessionConfig{CookieName: "session", CookiePath: "/", MaxAge: 3600}}, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.POST("/login", func(c *gin.Context) {
		if err := s.CreateSession(c, 1, "hash"); err != nil {
			t.Error(err)
		}
	})
	registerAPIRoutes(router, &routerDeps{authService: s, authHandlers: NewAuthHandlers(s, testFrontendURL, nil)})
	login := httptest.NewRecorder()
	router.ServeHTTP(login, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil))
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v, want one session cookie", cookies)
	}

	// The second logout reuses the cookie of the session that the first one ended.
	for _, want := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/v1/sessions/current", nil)
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("status = %d, want %d; body = %s", rec.Code, want, rec.Body)
		}
	}
}
