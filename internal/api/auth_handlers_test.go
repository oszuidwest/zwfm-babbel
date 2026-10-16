package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

const testFrontendURL = "https://app.example.com/"

func TestHandleOAuthCallbackLogLevels(t *testing.T) {
	tests := []struct {
		name         string
		query        url.Values
		wantLevel    string
		wantMsg      string
		wantMessage  string
		wantExchange bool
		wantProvider string
	}{
		{
			name:         "cancelled at provider",
			query:        url.Values{"error": {"access_denied"}, "error_description": {"User cancelled\nlevel=ERROR msg=forged"}},
			wantLevel:    "WARN",
			wantMsg:      "OIDC login rejected",
			wantMessage:  "OIDC login rejected: login was cancelled",
			wantProvider: "access_denied",
		},
		{
			name:         "other provider error",
			query:        url.Values{"error": {"<script>alert(1)</script>"}},
			wantLevel:    "WARN",
			wantMsg:      "OIDC login rejected",
			wantMessage:  "OIDC login rejected: identity provider did not complete the login",
			wantProvider: "<script>alert(1)</script>",
		},
		{
			name:        "missing code",
			query:       url.Values{},
			wantLevel:   "WARN",
			wantMsg:     "OIDC login rejected",
			wantMessage: "OIDC login rejected: missing authorization code",
		},
		{
			name:         "exchange failure",
			query:        url.Values{"code": {"used-code"}},
			wantLevel:    "ERROR",
			wantMsg:      "OIDC login failed",
			wantMessage:  "Login failed; try again or contact an administrator",
			wantExchange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, exchanges := newOAuthTestRouter(t)
			cookie, state := startOAuthFlow(t, router)
			logs := captureLogs(t)

			tt.query.Set("state", state)
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?"+tt.query.Encode(), nil)
			request.AddCookie(cookie)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
			}
			wantLocation := testFrontendURL + "?error=" + url.QueryEscape(tt.wantMessage)
			if got := recorder.Header().Get("Location"); got != wantLocation {
				t.Fatalf("Location = %q, want %q", got, wantLocation)
			}
			// oauth2 may retry with another client auth style, so only count presence.
			if got := exchanges.Load() > 0; got != tt.wantExchange {
				t.Fatalf("token endpoint called = %v, want %v", got, tt.wantExchange)
			}

			entry := findLogEntry(t, logs, tt.wantMsg)
			if entry["level"] != tt.wantLevel {
				t.Fatalf("log level = %v, want %s", entry["level"], tt.wantLevel)
			}
			if tt.wantProvider != "" {
				if entry["provider_error"] != tt.wantProvider {
					t.Fatalf("provider_error = %v, want %q", entry["provider_error"], tt.wantProvider)
				}
				if entry["provider_error_description"] != tt.query.Get("error_description") {
					t.Fatalf("provider_error_description = %v, want %q",
						entry["provider_error_description"], tt.query.Get("error_description"))
				}
			}
		})
	}
}

// newOAuthTestRouter serves the OAuth handlers against a fake OIDC provider
// whose token endpoint always fails.
func newOAuthTestRouter(t *testing.T) (*gin.Engine, *atomic.Int32) {
	t.Helper()

	exchanges := &atomic.Int32{}
	mux := http.NewServeMux()
	provider := httptest.NewServer(mux)
	t.Cleanup(provider.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 provider.URL,
			"authorization_endpoint": provider.URL + "/authorize",
			"token_endpoint":         provider.URL + "/token",
			"jwks_uri":               provider.URL + "/keys",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})

	authService, err := auth.NewService(&auth.Config{
		Method: config.AuthMethodOIDC,
		OIDC: auth.OIDCConfig{
			ProviderURL: provider.URL,
			ClientID:    "client-id",
			RedirectURL: "https://api.example.com/callback",
		},
		Session: auth.SessionConfig{
			MaxAge:     3600,
			CookieName: "babbel_session",
			CookiePath: "/",
			SecretKey:  strings.Repeat("k", 32),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	h := NewAuthHandlers(authService, testFrontendURL, nil)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(authService.SessionMiddleware())
	router.GET("/oauth", h.StartOAuthFlow)
	router.GET("/callback", h.HandleOAuthCallback)
	return router, exchanges
}

// startOAuthFlow returns the session cookie and the state sent to the provider.
func startOAuthFlow(t *testing.T, router *gin.Engine) (*http.Cookie, string) {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse provider redirect: %v", err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("StartOAuthFlow set no session cookie")
	}
	return cookies[0], location.Query().Get("state")
}

// captureLogs sends the default slog output to a buffer for this test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func findLogEntry(t *testing.T, logs *bytes.Buffer, msg string) map[string]any {
	t.Helper()

	for line := range strings.Lines(logs.String()) {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if entry["msg"] == msg {
			return entry
		}
	}
	t.Fatalf("no log entry with msg %q in:\n%s", msg, logs.String())
	return nil
}
