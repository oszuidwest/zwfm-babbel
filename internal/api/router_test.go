package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestCORSMiddlewareAllowedOrigin(t *testing.T) {
	t.Parallel()
	recorder := performCORSRequest(t, "https://app.example.com", "https://app.example.com/")

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want https://app.example.com", got)
	}
}

func TestCORSMiddlewareRejectsPrefixAttack(t *testing.T) {
	t.Parallel()
	recorder := performCORSRequest(t, "https://app.example.com.evil.test", "https://app.example.com")

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func performCORSRequest(t *testing.T, origin, allowedOrigins string) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(corsMiddleware(&config.Config{
		Server: config.ServerConfig{AllowedOrigins: allowedOrigins},
	}))
	router.GET("/", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	request.Header.Set("Origin", origin)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)
	return recorder
}
