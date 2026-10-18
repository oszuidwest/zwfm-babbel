package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
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

func TestDisabledOAuthCallbackMatchesStart(t *testing.T) {
	for _, frontendURL := range []string{"", "https://app.example.com"} {
		t.Run("frontend="+frontendURL, func(t *testing.T) {
			s, err := auth.NewService(&auth.Config{Method: config.AuthMethodLocal, Session: auth.SessionConfig{CookieName: "session", SecretKey: strings.Repeat("k", 32)}}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			h := NewAuthHandlers(s, frontendURL, nil)
			router := gin.New()
			// No session middleware: disabled callbacks must return before
			// reading a session or validating an OAuth state.
			router.GET("/start", h.StartOAuthFlow)
			router.GET("/callback", h.HandleOAuthCallback)
			logs := testutil.CaptureLogs(t, slog.LevelDebug)
			var startProblem map[string]any
			for _, route := range []string{"/start", "/callback"} {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, route, nil))
				var problem map[string]any
				if rec.Code != http.StatusNotFound || json.Unmarshal(rec.Body.Bytes(), &problem) != nil || problem["detail"] != "OAuth authentication is disabled" || rec.Header().Get("Location") != "" {
					t.Fatalf("%s: status = %d, body = %s, headers = %v", route, rec.Code, rec.Body, rec.Header())
				}
				delete(problem, "instance")
				if startProblem == nil {
					startProblem = problem
				} else if !reflect.DeepEqual(startProblem, problem) {
					t.Fatalf("callback problem = %v, want start problem %v", problem, startProblem)
				}
			}
			if logs.Len() != 0 {
				t.Fatalf("disabled OAuth logs = %s, want none", logs)
			}
		})
	}
}
