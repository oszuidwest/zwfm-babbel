package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
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

func TestCORSMiddlewareEmptyAllowlist(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{"", "https://app.example.com"} {
		recorder := performCORSRequest(t, origin, "")
		if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("origin %q: Access-Control-Allow-Origin = %q, want empty", origin, got)
		}
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

// A query string that url.ParseQuery rejects fails with 422 on every route
// except OPTIONS, before a handler can read it with the malformed pairs
// dropped. Well-formed query strings, such as OAuth callback, list and
// automation parameters, reach the handler.
func TestEngineRejectsMalformedQuery(t *testing.T) {
	t.Parallel()
	const origin = "https://app.example.com"
	cfg := &config.Config{
		Server:     config.ServerConfig{AllowedOrigins: origin},
		Auth:       config.AuthConfig{Method: config.AuthMethodLocal, SessionSecret: strings.Repeat("x", 32)},
		Automation: config.AutomationConfig{Key: "expected"},
	}
	authService, err := auth.NewService(buildAuthConfig(cfg), nil, nil)
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := setupEngine(cfg, authService, nil)
	registerPublicRoutes(router, &routerDeps{automationHandler: handlers.NewAutomationHandler(nil, nil, cfg, nil)})
	router.Any("/probe", func(c *gin.Context) {
		c.String(http.StatusOK, "reached")
	})
	router.GET("/stations/:id/bulletins", (&handlers.Handlers{}).GetStationBulletins)

	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
		wantField  string
	}{
		{name: "invalid escape in page", target: "/probe?page=%ZZ", wantStatus: 422, wantField: "query"},
		{name: "invalid escape wins over removed latest key", target: "/stations/1/bulletins?latest=1&x=%ZZ", wantStatus: 422, wantField: "query"},
		{name: "semicolon separator", target: "/probe?limit=5;page=2", wantStatus: 422, wantField: "query"},
		{name: "automation key behind semicolon", target: "/public/stations/1/bulletin.wav?key=expected;max_age=0", wantStatus: 422, wantField: "query"},
		{name: "automation key with invalid escape", target: "/public/stations/1/bulletin.wav?key=%ZZ&max_age=0", wantStatus: 422, wantField: "query"},
		{name: "unmatched route", target: "/missing?page=%ZZ", wantStatus: 422, wantField: "query"},
		{name: "POST", method: http.MethodPost, target: "/probe?page=%ZZ", wantStatus: 422, wantField: "query"},
		{name: "OPTIONS is not checked", method: http.MethodOptions, target: "/probe?page=%ZZ", wantStatus: 204},
		{name: "no query", target: "/probe", wantStatus: 200},
		{name: "OAuth callback parameters", target: "/probe?code=abc&state=x%2By%3D&error=", wantStatus: 200},
		{name: "list parameters", target: "/probe?filter[status]=active&sort=-id&limit=5&trashed=only", wantStatus: 200},
		{name: "escaped semicolon and key without value", target: "/probe?search=a%3Bb+c&flag", wantStatus: 200},
		{name: "invalid automation max_age", target: "/public/stations/1/bulletin.wav?key=expected&max_age=abc", wantStatus: 422, wantField: "max_age"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			request := httptest.NewRequestWithContext(t.Context(), method, tt.target, nil)
			request.Header.Set("Origin", origin)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
			// A cross-origin frontend can read the response only with this header.
			if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != origin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, origin)
			}
			if tt.wantStatus == http.StatusOK && recorder.Body.String() != "reached" {
				t.Fatalf("body = %q, want the handler's response", recorder.Body.String())
			}
			if tt.wantField == "" {
				return
			}
			var body struct {
				Errors []apperrors.FieldError `json:"errors"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v; body: %s", err, recorder.Body.String())
			}
			if len(body.Errors) != 1 || body.Errors[0].Field != tt.wantField || body.Errors[0].Code != apperrors.CodeInvalidFormat || body.Errors[0].Message == "" {
				t.Fatalf("errors = %+v, want one %s/invalid_format with a message", body.Errors, tt.wantField)
			}
		})
	}
}
