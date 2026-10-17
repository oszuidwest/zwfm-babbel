package api

import (
	"bytes"
	"encoding/json"
	"log"
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
		wantMessage  string
		wantExchange bool
	}{
		{
			name:        "cancelled at provider",
			query:       url.Values{"error": {"access_denied"}, "error_description": {"User cancelled\nlevel=ERROR msg=forged"}},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: login was cancelled",
		},
		{
			name:        "other provider error",
			query:       url.Values{"error": {"<script>alert(1)</script>"}},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: identity provider did not complete the login",
		},
		{
			name:        "empty provider error with code",
			query:       url.Values{"error": {""}, "code": {"valid-code"}},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: identity provider did not complete the login",
		},
		{
			name:        "missing code",
			query:       url.Values{},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: missing authorization code",
		},
		{
			name:         "exchange failure",
			query:        url.Values{"code": {"used-code"}},
			wantLevel:    "ERROR",
			wantMessage:  "Login failed; try again or contact an administrator",
			wantExchange: true,
		},
	}

	wantMsg := map[string]string{"WARN": "OIDC login rejected", "ERROR": "OIDC login failed"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, exchanged := newOAuthTestRouter(t)
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
			if got := exchanged.Load(); got != tt.wantExchange {
				t.Fatalf("token endpoint called = %v, want %v", got, tt.wantExchange)
			}

			// Unmarshal rejects an empty buffer and a second record.
			var entry map[string]any
			if err := json.Unmarshal(logs.Bytes(), &entry); err != nil ||
				entry["level"] != tt.wantLevel || entry["msg"] != wantMsg[tt.wantLevel] {
				t.Fatalf("logs = %s, want one %s %q record", logs, tt.wantLevel, wantMsg[tt.wantLevel])
			}
			// The provider values are logged only when the callback has an error parameter.
			_, wantProvider := tt.query["error"]
			providerErr, hasErr := entry["provider_error"]
			providerDesc, hasDesc := entry["provider_error_description"]
			if hasErr != wantProvider || hasDesc != wantProvider || wantProvider &&
				(providerErr != tt.query.Get("error") || providerDesc != tt.query.Get("error_description")) {
				t.Fatalf("logged provider_error = %v, provider_error_description = %v, want the query values only when error is set",
					providerErr, providerDesc)
			}
		})
	}
}

// newOAuthTestRouter serves the OAuth handlers against a fake OIDC provider
// whose token endpoint always fails.
func newOAuthTestRouter(t *testing.T) (*gin.Engine, *atomic.Bool) {
	t.Helper()

	exchanged := &atomic.Bool{}
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
		exchanged.Store(true)
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
	return router, exchanged
}

// startOAuthFlow returns the session cookie and the state sent to the provider.
func startOAuthFlow(t *testing.T, router *gin.Engine) (*http.Cookie, string) {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil || location.Query().Get("state") == "" {
		t.Fatalf("provider redirect %q (status %d) has no state: %v", recorder.Header().Get("Location"), recorder.Code, err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("StartOAuthFlow set no session cookie")
	}
	return cookies[0], location.Query().Get("state")
}

// captureLogs sends the slog default to a JSON buffer for one test. It swaps
// process-wide loggers, so do not use it in parallel tests.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, previousWriter, previousFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	// SetDefault also redirects the log package, and restoring the built-in
	// default handler does not undo that.
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
	return &buf
}
