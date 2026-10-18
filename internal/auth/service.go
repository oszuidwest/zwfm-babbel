// Package auth provides authentication and role-based authorization.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	oidcDiscoveryTimeout      = 30 * time.Second
	oauthInvalidStateAlertKey = "security:oauth:invalid-state"
	oauthMissingIDAlertKey    = "security:oauth:missing-id-token"
	oauthInvalidTokenAlertKey = "security:oauth:invalid-id-token"
)

// Service manages login sessions and role-based permissions.
type Service struct {
	oauthStateMu sync.Mutex
	config       *Config
	db           *gorm.DB
	enforcer     *casbin.Enforcer
	store        sessions.Store
	alerts       notify.Alerter
	oauth        *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// IsLocalEnabled reports whether local authentication is enabled.
func (s *Service) IsLocalEnabled() bool {
	return s.config.Method.SupportsLocal()
}

// IsOAuthEnabled reports whether OAuth/OIDC authentication is enabled.
func (s *Service) IsOAuthEnabled() bool {
	return s.config.Method.SupportsOIDC()
}

// NewService initializes sessions, permissions, and the configured login methods.
func NewService(cfg *Config, db *gorm.DB, alerts notify.Alerter) (*Service, error) {
	s := &Service{
		config: cfg,
		db:     db,
		alerts: notify.OrDiscard(alerts),
		store:  newSessionStore(cfg.Session),
	}

	if cfg.Method.SupportsOIDC() {
		if err := s.initializeOIDC(); err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC: %w", err)
		}
	}

	enforcer, err := s.initializeRBAC()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Casbin: %w", err)
	}
	s.enforcer = enforcer

	return s, nil
}

func (s *Service) initializeOIDC() error {
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, s.config.OIDC.ProviderURL)
	if err != nil {
		return err
	}

	s.oauth = &oauth2.Config{
		ClientID:     s.config.OIDC.ClientID,
		ClientSecret: s.config.OIDC.ClientSecret,
		RedirectURL:  s.config.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.config.OIDC.Scopes,
	}
	s.verifier = provider.Verifier(&oidc.Config{ClientID: s.config.OIDC.ClientID})
	return nil
}

func (s *Service) initializeRBAC() (*casbin.Enforcer, error) {
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)
`

	m, err := model.NewModelFromString(modelText)
	if err != nil {
		return nil, err
	}

	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}

	policies := [][]string{
		{"admin", "*", "*"},

		{"editor", "stations", "read"},
		{"editor", "stations", "write"},
		{"editor", "voices", "read"},
		{"editor", "voices", "write"},
		{"editor", "stories", "read"},
		{"editor", "stories", "write"},
		{"editor", "bulletins", "generate"},
		{"editor", "bulletins", "read"},
		{"editor", "users", "read"},
		{"editor", "settings:tts", "read"},
		{"editor", "pronunciation_rules", "read"},
		{"editor", "pronunciation_rules", "write"},

		{"viewer", "stations", "read"},
		{"viewer", "voices", "read"},
		{"viewer", "stories", "read"},
		{"viewer", "bulletins", "read"},
		{"viewer", "settings:tts", "read"},
		{"viewer", "pronunciation_rules", "read"},
	}

	for _, p := range policies {
		added, err := enforcer.AddPolicy(p)
		if err != nil {
			return nil, fmt.Errorf("failed to add RBAC policy %v: %w", p, err)
		}
		if !added {
			logger.Debug("RBAC policy already exists", "policy", p)
		}
	}

	return enforcer, nil
}

// SessionMiddleware returns middleware for the configured session store.
func (s *Service) SessionMiddleware() gin.HandlerFunc {
	return sessions.Sessions(s.config.Session.CookieName, s.store)
}

// Middleware validates the session user and loads their current role.
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		userID, ok := coerceInt64(session.Get(sessKeyUserID))
		if !ok {
			utils.ProblemAuthentication(c, "Authentication required")
			c.Abort()
			return
		}

		var user struct {
			ID          int64
			Role        string
			SuspendedAt *time.Time
		}

		err := s.db.WithContext(c.Request.Context()).
			Table("users").
			Select("id, role, suspended_at").
			Where("id = ?", userID).
			Where("deleted_at IS NULL").
			First(&user).Error
		if err != nil || user.SuspendedAt != nil {
			if saveErr := s.clearSessionUser(c); saveErr != nil {
				logger.Error("Failed to save session during cleanup", "error", saveErr)
			}
			utils.ProblemAuthentication(c, "Invalid session")
			c.Abort()
			return
		}

		SetUserContext(c, UserContext{
			UserID: user.ID,
			Role:   user.Role,
		})

		c.Next()
	}
}

// RequirePermission returns middleware that enforces role-based access control.
// It must run after Middleware.
func (s *Service) RequirePermission(obj Resource, act Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, roleOk := UserRole(c)
		if !roleOk {
			logger.Error("RequirePermission: user role not found in context")
			utils.ProblemAuthentication(c, "Authentication required")
			c.Abort()
			return
		}

		allowed, err := s.enforcer.Enforce(role, string(obj), string(act))
		if err != nil {
			utils.ProblemInternalServer(c, "Permission check failed")
			c.Abort()
			return
		}

		if !allowed {
			utils.ProblemCustom(c, utils.ProblemTypeInsufficientPermissions, "Insufficient Permissions", http.StatusForbidden, "Insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}

// LocalLogin authenticates credentials and creates a session.
func (s *Service) LocalLogin(c *gin.Context, username, password string) error {
	if !s.config.Method.SupportsLocal() {
		return fmt.Errorf("local authentication is disabled")
	}

	var user struct {
		ID           int64
		PasswordHash string
		SuspendedAt  *time.Time
		LockedUntil  *time.Time
	}

	ctx := c.Request.Context()
	err := s.db.WithContext(ctx).
		Table("users").
		Select("id, password_hash, suspended_at, locked_until").
		Where("username = ?", username).
		Where("deleted_at IS NULL").
		First(&user).Error
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}

	if user.SuspendedAt != nil {
		return fmt.Errorf("account is suspended")
	}

	now := time.Now()
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		return fmt.Errorf("account is locked")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		locked, updateErr := s.updateLoginFailure(ctx, user.ID, now)
		if updateErr != nil {
			logger.Error("Failed to update login failure stats", "error", updateErr)
		} else if locked {
			s.alerts.Alert(ctx, notify.Event{
				Key:     accountLockoutAlertKey(user.ID),
				Summary: "Account locked after repeated failed logins",
				Details: fmt.Sprintf("User ID %d reached the configured failed-login threshold.", user.ID),
			})
		}
		return fmt.Errorf("invalid credentials")
	}

	if err := s.updateLoginSuccess(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to update login stats: %w", err)
	}
	s.alerts.Resolve(ctx, accountLockoutAlertKey(user.ID),
		"Account lockout cleared", fmt.Sprintf("User ID %d successfully logged in again.", user.ID))

	return s.CreateSession(c, user.ID)
}

// StartOAuthFlow saves the login state and redirects to the OIDC provider.
func (s *Service) StartOAuthFlow(c *gin.Context) {
	if !s.config.Method.SupportsOIDC() {
		utils.ProblemCustom(c, utils.ProblemTypeResourceNotFound, "Resource Not Found", http.StatusNotFound,
			"OAuth authentication is disabled")
		return
	}

	// Bind the callback to this session to prevent login CSRF.
	state := rand.Text()

	s.oauthStateMu.Lock()
	defer s.oauthStateMu.Unlock()
	session := sessions.Default(c)
	session.Set(sessKeyOAuthState, state)

	if frontendURL := c.Query("frontend_url"); frontendURL != "" {
		if s.isAllowedFrontendURL(frontendURL) {
			session.Set(sessKeyFrontendURL, frontendURL)
		} else {
			logger.Warn("Rejected invalid frontend_url", "url", logger.TruncateValue(frontendURL), "url_bytes", len(frontendURL))
		}
	}
	if err := session.Save(); err != nil {
		logger.Error("Failed to save OAuth session", "error", err)
		utils.ProblemInternalServer(c, "Session error")
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, s.oauth.AuthCodeURL(state))
}

// FinishOAuthFlow validates the OIDC callback and creates a session.
func (s *Service) FinishOAuthFlow(c *gin.Context) error {
	if err := s.consumeOAuthState(c); err != nil {
		if errors.Is(err, ErrLoginRejected) {
			s.alerts.Alert(c.Request.Context(), notify.Event{
				Key:     oauthInvalidStateAlertKey,
				Summary: "OAuth callback has an invalid CSRF state",
				Details: "The OAuth callback state was missing or did not match the server-side session.",
			})
		}
		return err
	}
	s.alerts.Resolve(c.Request.Context(), oauthInvalidStateAlertKey,
		"OAuth callback state validation recovered", "The OAuth callback state matches the server-side session again.")

	// access_denied means the user cancelled or the provider denied the user. Any
	// other error code points to the provider or the client configuration (RFC
	// 6749 section 4.1.2.1), which an administrator must see. An empty error
	// parameter is a malformed callback, not a success response. The provider's
	// values stay out of the error text, which the user sees for a rejection.
	if providerErr, ok := c.GetQuery("error"); ok {
		switch providerErr {
		case "access_denied":
			return fmt.Errorf("%w: login was cancelled or denied at the identity provider", ErrLoginRejected)
		case "":
			return fmt.Errorf("%w: invalid callback from the identity provider", ErrLoginRejected)
		}
		return fmt.Errorf("identity provider returned an error")
	}
	code := c.Query("code")
	if code == "" {
		return fmt.Errorf("%w: missing authorization code", ErrLoginRejected)
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	token, err := s.oauth.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		s.alerts.Alert(c.Request.Context(), notify.Event{
			Key: oauthMissingIDAlertKey, Summary: "OAuth response is missing an ID token",
			Details: "The identity provider returned no usable id_token.",
		})
		return fmt.Errorf("no id_token in response")
	}
	s.alerts.Resolve(c.Request.Context(), oauthMissingIDAlertKey,
		"OAuth ID token restored", "The identity provider returned an ID token again.")

	idToken, err := s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.alerts.Alert(c.Request.Context(), notify.Event{
			Key: oauthInvalidTokenAlertKey, Summary: "OAuth ID token verification failed",
			Details: err.Error(),
		})
		return fmt.Errorf("failed to verify ID token: %w", err)
	}
	s.alerts.Resolve(c.Request.Context(), oauthInvalidTokenAlertKey,
		"OAuth ID token verification recovered", "The identity provider returned a verifiable ID token again.")

	var claims oauthClaims
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	// go-oidc only verifies tokens from ProviderURL or its Google alias, so
	// ProviderURL is the canonical issuer.
	userID, err := s.findOrCreateOAuthUser(ctx, oauthIdentity{
		Issuer: s.config.OIDC.ProviderURL, Subject: idToken.Subject, Claims: claims,
	})
	if err != nil {
		return err
	}

	if err := s.updateLoginSuccess(c.Request.Context(), userID); err != nil {
		return fmt.Errorf("failed to update login stats: %w", err)
	}

	if err := s.CreateSession(c, userID); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// consumeOAuthState reloads and consumes state under one lock. The handler
// can already have cached a session snapshot while reading its frontend URL;
// checking that snapshot would allow concurrent callbacks to reuse the state.
// The configured store is local memory, so the critical section has no remote I/O.
func (s *Service) consumeOAuthState(c *gin.Context) error {
	s.oauthStateMu.Lock()
	defer s.oauthStateMu.Unlock()
	// The memory store fails only to decode a cookie, and then returns an
	// empty session that fails the check below.
	session, _ := s.store.New(c.Request, s.config.Session.CookieName)
	savedState, ok := session.Values[sessKeyOAuthState].(string)
	if !ok || c.Query("state") != savedState {
		return fmt.Errorf("%w: invalid or expired login state", ErrLoginRejected)
	}
	delete(session.Values, sessKeyOAuthState)
	delete(session.Values, sessKeyFrontendURL)
	if err := s.store.Save(c.Request, c.Writer, session); err != nil {
		return fmt.Errorf("failed to consume OAuth login state: %w", err)
	}
	// CreateSession drops the keys from this request's cached copy.
	return nil
}

// clearSessionUser removes the user from the stored session. It reloads under
// the OAuth state lock: saving this request's snapshot could restore a state
// that a concurrent callback consumed, or drop a fresh one.
func (s *Service) clearSessionUser(c *gin.Context) error {
	s.oauthStateMu.Lock()
	defer s.oauthStateMu.Unlock()
	session, _ := s.store.New(c.Request, s.config.Session.CookieName)
	delete(session.Values, sessKeyUserID)
	return s.store.Save(c.Request, c.Writer, session)
}

// Logout clears and saves the current session.
func (s *Service) Logout(c *gin.Context) error {
	session := sessions.Default(c)
	session.Clear()
	if err := session.Save(); err != nil {
		logger.Error("Failed to save session during logout", "error", err)
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// CreateSession stores the authenticated user's ID in the session.
// Middleware reads their role from the database on each request.
func (s *Service) CreateSession(c *gin.Context, userID int64) error {
	session := sessions.Default(c)
	session.Set(sessKeyUserID, userID)
	// A login ends any pending OAuth flow; this save must not restore a state
	// that a concurrent callback consumed after this request loaded it.
	session.Delete(sessKeyOAuthState)
	session.Delete(sessKeyFrontendURL)
	return session.Save()
}

func (s *Service) updateLoginSuccess(ctx context.Context, userID int64) error {
	err := s.db.WithContext(ctx).
		Table("users").
		Where("id = ?", userID).
		Updates(map[string]any{
			"last_login_at":         time.Now(),
			"login_count":           gorm.Expr("login_count + 1"),
			"failed_login_attempts": 0,
			"locked_until":          nil,
		}).Error
	if err != nil {
		logger.Error("Failed to update login stats", "error", err)
	}
	return err
}

func accountLockoutAlertKey(userID int64) string {
	return fmt.Sprintf("security:account-lockout:user:%d", userID)
}

// updateLoginFailure records a failure and reports whether the account is locked.
// Expired locks reset the count to 1; active locks remain unchanged.
//
// MySQL evaluates SET assignments left-to-right, so the lockout check uses
// the incremented count.
func (s *Service) updateLoginFailure(ctx context.Context, userID int64, now time.Time) (bool, error) {
	lockoutDuration := time.Duration(s.config.Local.LockoutDurationMinutes) * time.Minute
	maxAttempts := s.config.Local.MaxFailedAttempts

	query := `
UPDATE users
SET
	failed_login_attempts = CASE
		WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
		ELSE failed_login_attempts + 1
	END,
	locked_until = NULL
WHERE id = ? AND (locked_until IS NULL OR locked_until <= ?)`
	args := []any{now, userID, now}

	if maxAttempts > 0 && lockoutDuration > 0 {
		query = `
UPDATE users
SET
	failed_login_attempts = CASE
		WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
		ELSE failed_login_attempts + 1
	END,
	locked_until = CASE
		WHEN failed_login_attempts >= ? THEN ?
		ELSE NULL
	END
WHERE id = ? AND (locked_until IS NULL OR locked_until <= ?)`
		args = []any{now, maxAttempts, now.Add(lockoutDuration), userID, now}
	}

	err := s.db.WithContext(ctx).Exec(query, args...).Error
	if err != nil {
		logger.Error("Failed to update failed login attempts", "error", err)
		return false, err
	}

	var lockState struct {
		LockedUntil *time.Time
	}
	if err := s.db.WithContext(ctx).Table("users").Select("locked_until").Where("id = ?", userID).Scan(&lockState).Error; err != nil {
		return false, fmt.Errorf("read account lock state: %w", err)
	}
	return lockState.LockedUntil != nil && lockState.LockedUntil.After(now), nil
}

func (s *Service) isAllowedFrontendURL(urlStr string) bool {
	return config.IsURLAllowedByOrigin(urlStr, s.config.AllowedOrigins)
}
