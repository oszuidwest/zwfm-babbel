package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestMiddlewareEndsSessionOnlyForMissingUser(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		disconnect bool
		wantStatus int
		wantKept   bool
	}{
		{name: "user found", wantStatus: http.StatusOK, wantKept: true},
		{name: "user gone", err: gorm.ErrRecordNotFound, wantStatus: http.StatusUnauthorized},
		{name: "database failure", err: errors.New("connection refused"), wantStatus: http.StatusInternalServerError, wantKept: true},
		{name: "client left during a database failure", err: errors.New("invalid connection"), disconnect: true, wantStatus: 499, wantKept: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := testutil.CaptureLogs(t, slog.LevelError)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			db, err := gorm.Open(mysql.New(mysql.Config{DSN: "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel", SkipInitializeWithVersion: true}),
				&gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.Callback().Query().Before("gorm:query").Register("test:fail-lookup", func(tx *gorm.DB) {
				if tt.disconnect {
					cancel()
				}
				_ = tx.AddError(tt.err)
			}); err != nil {
				t.Fatal(err)
			}

			cfg := &Config{Session: SessionConfig{CookieName: "session", CookiePath: "/", MaxAge: 3600}}
			s := &Service{config: cfg, db: db, store: newSessionStore(cfg.Session), alerts: notify.Discard}
			handlerRan := false
			router := gin.New()
			router.Use(s.SessionMiddleware())
			router.POST("/login", func(c *gin.Context) {
				if err := s.CreateSession(c, 7, ""); err != nil {
					t.Error(err)
				}
			})
			router.GET("/kept", func(c *gin.Context) {
				if _, ok := coerceInt64(sessions.Default(c).Get(sessKeyUserID)); !ok {
					c.Status(http.StatusGone)
				}
			})
			router.GET("/protected", s.Middleware(), func(*gin.Context) { handlerRan = true })

			login := httptest.NewRecorder()
			router.ServeHTTP(login, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil))
			cookies := login.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookies = %v, want one session cookie", cookies)
			}

			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/protected", nil)
			req.AddCookie(cookies[0])
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			wantCause := tt.wantStatus == http.StatusInternalServerError
			loggedCause := tt.err != nil && strings.Contains(logs.String(), tt.err.Error())
			if rec.Code != tt.wantStatus || handlerRan != (tt.err == nil) || loggedCause != wantCause {
				t.Fatalf("status = %d, want %d; handler ran = %v; logs = %s", rec.Code, tt.wantStatus, handlerRan, logs)
			}

			req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/kept", nil)
			req.AddCookie(cookies[0])
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if kept := rec.Code != http.StatusGone; kept != tt.wantKept {
				t.Fatalf("session kept = %v, want %v", kept, tt.wantKept)
			}
		})
	}
}
