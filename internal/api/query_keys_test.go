package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"gorm.io/gorm"
)

func TestAuthSingletonGETsRejectQueryBeforeReadingSession(t *testing.T) {
	t.Parallel()
	h := &AuthHandlers{}
	for name, handler := range map[string]gin.HandlerFunc{"current session": h.GetCurrentUser, "auth config": h.GetAuthConfig} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/singleton?fields=x", nil)
			handler(c) // No session middleware or service: validation must run first.
			var problem struct {
				Errors []apperrors.FieldError `json:"errors"`
			}
			if rec.Code != http.StatusUnprocessableEntity || json.Unmarshal(rec.Body.Bytes(), &problem) != nil ||
				len(problem.Errors) != 1 || problem.Errors[0].Field != "fields" || problem.Errors[0].Code != "unknown_field" {
				t.Fatalf("response = %d %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestHealthStillIgnoresQueryKeys(t *testing.T) {
	router := gin.New()
	registerHealthRoute(router, &gorm.DB{Config: &gorm.Config{}}, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health?probe=1", nil))
	if rec.Code == http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want the health check, not query validation", rec.Code)
	}
}
