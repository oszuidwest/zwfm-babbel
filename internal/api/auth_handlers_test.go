package api

import (
	"cmp"
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
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
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
			wantMessage: "OIDC login rejected: login was cancelled or denied at the identity provider",
		},
		{
			name:        "provider error that is not a user action",
			query:       url.Values{"error": {"server_error"}, "error_description": {"<script>alert(1)</script>"}},
			wantLevel:   "ERROR",
			wantMessage: "Login failed; try again or contact an administrator",
		},
		{
			name:        "empty provider error with code",
			query:       url.Values{"error": {""}, "code": {"valid-code"}},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: invalid callback from the identity provider",
		},
		{
			name:        "invalid state with provider error",
			query:       url.Values{"state": {"forged"}, "error": {"access_denied"}},
			wantLevel:   "WARN",
			wantMessage: "OIDC login rejected: invalid or expired login state",
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
			logs := testutil.CaptureLogs(t, slog.LevelDebug)

			tt.query.Set("state", cmp.Or(tt.query.Get("state"), state))
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
			// A rejection logs the text the user sees, which says why.
			if tt.wantLevel == "WARN" && entry["error"] != tt.wantMessage {
				t.Fatalf("logged error = %v, want %q", entry["error"], tt.wantMessage)
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

func TestHandleOAuthCallbackTruncatesProviderValues(t *testing.T) {
	router, _ := newOAuthTestRouter(t)
	cookie, state := startOAuthFlow(t, router)
	logs := testutil.CaptureLogs(t, slog.LevelDebug)

	long := strings.Repeat("x", 100_000)
	query := url.Values{"state": {state}, "error": {long}, "error_description": {long}}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback?"+query.Encode(), nil)
	request.AddCookie(cookie)
	router.ServeHTTP(httptest.NewRecorder(), request)

	// The bound covers every attribute, also one that would copy a provider value.
	if logs.Len() == 0 || logs.Len() > 4*logger.MaxValueBytes {
		t.Fatalf("log is %d bytes, want 1 to %d", logs.Len(), 4*logger.MaxValueBytes)
	}
}

func TestFailedOAuthCallbackConsumesState(t *testing.T) {
	for _, query := range []string{"error=access_denied", "error=server_error", "", "code=used-code"} {
		t.Run(cmp.Or(query, "missing code"), func(t *testing.T) {
			router, exchanged := newOAuthTestRouter(t)
			cookie, state := startOAuthFlow(t, router)
			callback := "/callback?state=" + url.QueryEscape(state) + "&" + query
			for attempt := range 2 {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callback, nil)
				req.AddCookie(cookie)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusSeeOther {
					t.Fatalf("attempt %d: status = %d", attempt, rec.Code)
				}
				if attempt == 0 {
					exchanged.Store(false)
					continue
				}
				location, err := url.Parse(rec.Header().Get("Location"))
				if err != nil || location.Query().Get("error") != "OIDC login rejected: invalid or expired login state" {
					t.Fatalf("replayed callback: Location = %q, parse error = %v", rec.Header().Get("Location"), err)
				}
				if exchanged.Load() {
					t.Fatal("replayed callback reached the token endpoint")
				}
			}
		})
	}
}

func TestStartOAuthFlowBoundsRejectedFrontendLog(t *testing.T) {
	router, _ := newOAuthTestRouter(t)
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	value := "https://untrusted.example/" + strings.Repeat("x", 1<<20)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oauth?frontend_url="+url.QueryEscape(value), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want redirect", rec.Code)
	}
	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	logged, ok := record["url"].(string)
	if !ok || logged != value[:logger.MaxValueBytes]+" (truncated)" || record["url_bytes"] != float64(len(value)) ||
		record["level"] != "WARN" || record["msg"] != "Rejected invalid frontend_url" {
		t.Fatalf("logged URL length = %d, url_bytes = %v; want a bounded prefix and original length", len(logged), record["url_bytes"])
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
