package api

import (
	"cmp"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"golang.org/x/crypto/bcrypt"
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

// TestLoginTellsRejectionFromDatabaseFailure checks that Login answers 401 only
// for refused credentials and 500 with an error log for database failures. A
// 401 takes at least one bcrypt run, like a wrong password does.
func TestLoginTellsRejectionFromDatabaseFailure(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		password   string
		hash       *string // Replaces the valid hash.
		suspended  *time.Time
		lockedTill *time.Time
		lookupErr  error
		writeErr   error
		wantStatus int
	}{
		{name: "user lookup fails", lookupErr: errors.New("connection refused"), wantStatus: http.StatusInternalServerError},
		{name: "unknown user", lookupErr: gorm.ErrRecordNotFound, wantStatus: http.StatusUnauthorized},
		{name: "suspended user", suspended: new(time.Now()), wantStatus: http.StatusUnauthorized},
		{name: "suspended user without a password", suspended: new(time.Now()), hash: new(""), wantStatus: http.StatusUnauthorized},
		{name: "suspended user with an invalid salt", suspended: new(time.Now()), hash: new("$2a$10$!!!!!!!!!!!!!!!!!!!!!!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), wantStatus: http.StatusUnauthorized},
		{name: "locked user", lockedTill: new(time.Now().Add(time.Hour)), wantStatus: http.StatusUnauthorized},
		{name: "login stats update fails", writeErr: errors.New("connection refused"), wantStatus: http.StatusInternalServerError},
		{name: "failed attempt count fails", password: "wrong", writeErr: errors.New("connection refused"), wantStatus: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := gorm.Open(mysql.New(mysql.Config{DSN: "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel", SkipInitializeWithVersion: true}),
				&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Callback().Query().Before("gorm:query").Register("test:lookup", func(tx *gorm.DB) {
				if tt.lookupErr != nil {
					_ = tx.AddError(tt.lookupErr)
					return
				}
				user := reflect.ValueOf(tx.Statement.Dest).Elem()
				user.FieldByName("ID").SetInt(7)
				passwordHash := string(hash)
				if tt.hash != nil {
					passwordHash = *tt.hash
				}
				user.FieldByName("PasswordHash").SetString(passwordHash)
				user.FieldByName("SuspendedAt").Set(reflect.ValueOf(tt.suspended))
				user.FieldByName("LockedUntil").Set(reflect.ValueOf(tt.lockedTill))
			}); err != nil {
				t.Fatal(err)
			}
			failWrite := func(tx *gorm.DB) { _ = tx.AddError(tt.writeErr) }
			if err := db.Callback().Update().Before("gorm:update").Register("test:update", failWrite); err != nil {
				t.Fatal(err)
			}
			if err := db.Callback().Raw().Before("gorm:raw").Register("test:raw", failWrite); err != nil {
				t.Fatal(err)
			}
			s, err := auth.NewService(&auth.Config{Method: config.AuthMethodLocal, Session: auth.SessionConfig{CookieName: "session"}}, db, nil)
			if err != nil {
				t.Fatal(err)
			}
			logs := testutil.CaptureLogs(t, slog.LevelError)
			router := gin.New()
			router.Use(s.SessionMiddleware())
			router.POST("/sessions", NewAuthHandlers(s, testFrontendURL, nil).Login)
			rec := httptest.NewRecorder()
			body := strings.NewReader(`{"username":"admin","password":"` + cmp.Or(tt.password, "secret") + `"}`)
			start := time.Now()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/sessions", body))
			if rec.Code == http.StatusUnauthorized && time.Since(start) < 10*time.Millisecond {
				t.Fatalf("401 after %v, want at least one bcrypt run", time.Since(start))
			}
			if rec.Code != tt.wantStatus || strings.Contains(logs.String(), "connection refused") != (tt.wantStatus == http.StatusInternalServerError) {
				t.Fatalf("status = %d, want %d; logs = %s", rec.Code, tt.wantStatus, logs)
			}
		})
	}
}
