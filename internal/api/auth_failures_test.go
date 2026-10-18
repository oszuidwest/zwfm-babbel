package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestGetCurrentUserLogsPermissionCause(t *testing.T) {
	cause := errors.New("evaluate stories/read permission: evaluator unavailable")
	h := &AuthHandlers{permissions: func(role string) (auth.PermissionSet, error) {
		if role != "viewer" {
			t.Errorf("role = %q", role)
		}
		return nil, cause
	}}
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/sessions/current", nil)
	auth.SetUserContext(c, auth.UserContext{UserID: 7, Role: "viewer"})
	h.GetCurrentUser(c)
	var record map[string]any
	if rec.Code != http.StatusInternalServerError || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" ||
		record["role"] != "viewer" || record["resource"] != "sessions/current" || record["action"] != "read" || record["error"] != cause.Error() {
		t.Fatalf("status = %d, logs = %s", rec.Code, logs)
	}
}

func TestOAuthCallbackLogsMissingFrontendConfiguration(t *testing.T) {
	s, err := auth.NewService(&auth.Config{Method: config.AuthMethodLocal, Session: auth.SessionConfig{CookieName: "session", SecretKey: strings.Repeat("k", 32)}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandlers(s, "", nil)
	router := gin.New()
	router.Use(s.SessionMiddleware())
	router.GET("/callback", h.HandleOAuthCallback)
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil))
	var record map[string]any
	if rec.Code != http.StatusInternalServerError || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" ||
		!strings.Contains(record["error"].(string), "BABBEL_FRONTEND_URL") {
		t.Fatalf("status = %d, logs = %s", rec.Code, logs)
	}
}
