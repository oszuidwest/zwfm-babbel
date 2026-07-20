// Package auth provides authentication and authorization services for the Babbel API.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
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

// Service handles authentication and authorization.
type Service struct {
	config   *Config
	db       *gorm.DB
	enforcer *casbin.Enforcer
	sessions SessionStore
	ginStore sessions.Store
	alerts   notify.Alerter
}

// IsLocalEnabled reports whether local authentication is enabled.
func (s *Service) IsLocalEnabled() bool {
	return s.config.Method.SupportsLocal()
}

// IsOAuthEnabled reports whether OAuth/OIDC authentication is enabled.
func (s *Service) IsOAuthEnabled() bool {
	return s.config.Method.SupportsOIDC()
}

// NewService initializes session storage, OIDC, and RBAC for authentication.
func NewService(cfg *Config, db *gorm.DB, alerts notify.Alerter) (*Service, error) {
	alerts = notify.OrDiscard(alerts)
	s := &Service{
		config: cfg,
		db:     db,
		alerts: alerts,
	}

	if cfg.Method.SupportsOIDC() {
		if err := s.initializeOIDC(); err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC: %w", err)
		}
	}

	store, ginStore, err := NewGinSessionStore(cfg.Session)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session store: %w", err)
	}
	s.sessions = store
	s.ginStore = ginStore

	enforcer, err := s.initializeRBAC()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Casbin: %w", err)
	}
	s.enforcer = enforcer

	return s, nil
}

// initializeOIDC configures the OIDC provider for OAuth authentication.
func (s *Service) initializeOIDC() error {
	ctx, cancel := context.WithTimeout(context.Background(), oidcDiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, s.config.OIDC.ProviderURL)
	if err != nil {
		return err
	}

	s.config.OIDC.Provider = provider

	// Configure OAuth2 when OIDC is enabled.
	s.config.OIDC.OAuth2Config = &oauth2.Config{
		ClientID:     s.config.OIDC.ClientID,
		ClientSecret: s.config.OIDC.ClientSecret,
		RedirectURL:  s.config.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.config.OIDC.Scopes,
	}

	return nil
}

// initializeRBAC sets up role-based access control using Casbin.
func (s *Service) initializeRBAC() (*casbin.Enforcer, error) {
	// Define the RBAC model inline.
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

	// Define default policies.
	policies := [][]string{
		// Admins can do everything: the keyMatch matcher expands "*" to cover
		// every resource and action, so no per-resource admin rows are needed.
		{"admin", "*", "*"},

		// Editors can manage content.
		{"editor", "stations", "read"},
		{"editor", "stations", "write"},
		{"editor", "voices", "read"},
		{"editor", "voices", "write"},
		{"editor", "stories", "read"},
		{"editor", "stories", "write"},
		{"editor", "bulletins", "generate"},
		{"editor", "bulletins", "read"},
		{"editor", "users", "read"}, // Can view users
		{"editor", "settings:tts", "read"},
		{"editor", "pronunciation_rules", "read"},
		{"editor", "pronunciation_rules", "write"},

		// Viewers can only read.
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
			// Existing policies from the database adapter are expected.
			logger.Debug("RBAC policy already exists", "policy", p)
		}
	}

	return enforcer, nil
}

// usernameSanitizeRe matches characters that are not allowed in usernames.
var usernameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeEmailToUsername converts an email address to a valid username.
func (s *Service) sanitizeEmailToUsername(email string) string {
	base, _, _ := strings.Cut(email, "@")

	username := usernameSanitizeRe.ReplaceAllString(base, "_")

	if len(username) < 3 {
		if _, domainStr, found := strings.Cut(email, "@"); found {
			domainPart, _, _ := strings.Cut(domainStr, ".")
			domainPart = usernameSanitizeRe.ReplaceAllString(domainPart, "_")
			username = username + "_" + domainPart
		}
	}

	if len(username) > 100 {
		username = username[:100]
	}

	return s.ensureUniqueUsername(username)
}

// ensureUniqueUsername returns a unique username, adding numeric suffixes if needed.
func (s *Service) ensureUniqueUsername(baseUsername string) string {
	username := baseUsername
	counter := 1
	ctx := context.Background()

	for {
		var count int64
		err := s.db.WithContext(ctx).Table("users").Where("username = ?", username).Where("deleted_at IS NULL").Count(&count).Error
		if err != nil {
			// On errors, assume the username might exist and retry with a suffix.
			logger.Warn("Database error checking username uniqueness, trying next", "error", err)
			username = fmt.Sprintf("%s_%d", baseUsername, counter)
			counter++
			if counter > 100 {
				// Fall back to a timestamp-based username to avoid an infinite loop.
				username = fmt.Sprintf("%s_%d", baseUsername, time.Now().Unix())
				break
			}
			continue
		}

		if count == 0 {
			break
		}

		// Existing usernames are retried with a numeric suffix.
		username = fmt.Sprintf("%s_%d", baseUsername, counter)
		counter++

		// Ensure we don't exceed the max length (100 characters)
		if len(username) > 100 {
			// Truncate the base username before adding the suffix.
			maxBaseLen := max(100-len(fmt.Sprintf("_%d", counter)), 90)
			truncatedBase := baseUsername[:min(len(baseUsername), maxBaseLen)]
			username = fmt.Sprintf("%s_%d", truncatedBase, counter)
		}
	}

	return username
}

// SessionMiddleware returns the Gin session middleware backed by the
// configured gin-contrib session store.
func (s *Service) SessionMiddleware() gin.HandlerFunc {
	return sessions.Sessions(s.config.Session.CookieName, s.ginStore)
}

// Middleware loads the authenticated user from the session and attaches the
// current user context for downstream handlers.
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := s.sessions.Get(c)

		userID, ok := SessionUserID(session)
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
			session.Delete(string(SessKeyUserID))
			if saveErr := session.Save(c); saveErr != nil {
				logger.Error("Failed to save session during cleanup", "error", saveErr)
				// Continue with the authentication error because session cleanup failure is secondary.
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

// LocalLogin authenticates a user using username and password.
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

// StartOAuthFlow initiates the OAuth/OIDC authentication process.
func (s *Service) StartOAuthFlow(c *gin.Context) {
	if !s.config.Method.SupportsOIDC() {
		utils.ProblemBadRequest(c, "OAuth authentication is disabled")
		return
	}

	// Cryptographically secure random state for OAuth2 CSRF protection.
	state := rand.Text()

	session := s.sessions.Get(c)
	SetSessionOAuthState(session, state)

	frontendURL := c.Query("frontend_url")
	if frontendURL != "" {
		if s.isAllowedFrontendURL(frontendURL) {
			SetSessionFrontendURL(session, frontendURL)
		} else {
			logger.Warn("Rejected invalid frontend_url", "url", frontendURL)
		}
	}
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save OAuth session", "error", err)
		utils.ProblemInternalServer(c, "Session error")
		return
	}

	url := s.config.OIDC.OAuth2Config.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// FinishOAuthFlow completes the OAuth authentication process.
func (s *Service) FinishOAuthFlow(c *gin.Context) error {
	session := s.sessions.Get(c)

	state := c.Query("state")
	savedStateStr, ok := SessionOAuthState(session)
	if !ok || state != savedStateStr {
		s.alerts.Alert(c.Request.Context(), notify.Event{
			Key:     oauthInvalidStateAlertKey,
			Summary: "OAuth callback has an invalid CSRF state",
			Details: "The OAuth callback state was missing or did not match the server-side session.",
		})
		return fmt.Errorf("invalid state")
	}
	s.alerts.Resolve(c.Request.Context(), oauthInvalidStateAlertKey,
		"OAuth callback state validation recovered", "The OAuth callback state matches the server-side session again.")
	session.Delete(string(SessKeyOAuthState))

	code := c.Query("code")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	token, err := s.config.OIDC.OAuth2Config.Exchange(ctx, code)
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

	verifier := s.config.OIDC.Provider.Verifier(&oidc.Config{
		ClientID: s.config.OIDC.ClientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.alerts.Alert(c.Request.Context(), notify.Event{
			Key: oauthInvalidTokenAlertKey, Summary: "OAuth ID token verification failed",
			Details: err.Error(),
		})
		return fmt.Errorf("failed to verify ID token: %w", err)
	}
	s.alerts.Resolve(c.Request.Context(), oauthInvalidTokenAlertKey,
		"OAuth ID token verification recovered", "The identity provider returned a verifiable ID token again.")

	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	userID, err := s.findOrCreateOAuthUser(c.Request.Context(), claims.Email, claims.Name, claims.PreferredUsername)
	if err != nil {
		return err
	}

	return s.setupOAuthSession(c, userID)
}

// findOrCreateOAuthUser resolves an OAuth identity to an active local user
// and returns its ID.
func (s *Service) findOrCreateOAuthUser(ctx context.Context, email, fullName, preferredUsername string) (int64, error) {
	var existingUser struct {
		ID          int64
		SuspendedAt *time.Time
	}

	err := s.db.WithContext(ctx).
		Table("users").
		Select("id, suspended_at").
		Where("email = ?", email).
		Where("deleted_at IS NULL").
		First(&existingUser).Error
	if err == nil {
		if existingUser.SuspendedAt != nil {
			return 0, fmt.Errorf("account is suspended")
		}
		return existingUser.ID, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, fmt.Errorf("failed to query user: %w", err)
	}

	username := s.determineOAuthUsername(preferredUsername, email)
	now := time.Now()

	// Insert raw columns because models.User omits fields needed for OAuth bootstrap.
	newUser := map[string]any{
		"username":      username,
		"full_name":     fullName,
		"email":         email,
		"role":          "viewer",
		"password_hash": "",
		"last_login_at": now,
		"login_count":   1,
	}

	result := s.db.WithContext(ctx).Table("users").Create(newUser)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to create user: %w", result.Error)
	}

	var id int64
	err = s.db.WithContext(ctx).Raw("SELECT LAST_INSERT_ID()").Scan(&id).Error
	if err != nil {
		return 0, fmt.Errorf("failed to get created user ID: %w", err)
	}

	return id, nil
}

// determineOAuthUsername determines the best username from OAuth claims.
func (s *Service) determineOAuthUsername(preferredUsername, email string) string {
	username := preferredUsername
	if username == "" {
		return s.sanitizeEmailToUsername(email)
	}

	if strings.Contains(username, "@") || strings.Contains(username, ".") {
		return s.sanitizeEmailToUsername(username)
	}

	return username
}

// setupOAuthSession creates a session for an OAuth-authenticated user.
func (s *Service) setupOAuthSession(c *gin.Context, userID int64) error {
	if err := s.updateLoginSuccess(c.Request.Context(), userID); err != nil {
		return fmt.Errorf("failed to update login stats: %w", err)
	}

	if err := s.CreateSession(c, userID); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// Session retrieves the current session for the request context.
func (s *Service) Session(c *gin.Context) Session {
	return s.sessions.Get(c)
}

// Logout destroys the user session and returns an error if session save fails.
func (s *Service) Logout(c *gin.Context) error {
	session := s.sessions.Get(c)
	session.Clear()
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save session during logout", "error", err)
		return fmt.Errorf("failed to save session: %w", err)
	}
	return nil
}

// CreateSession stores the authenticated user's ID in the session. All other
// user attributes (username, role) are re-read from the database per request
// by Middleware, so only the ID is persisted.
func (s *Service) CreateSession(c *gin.Context, userID int64) error {
	session := s.sessions.Get(c)
	session.Set(string(SessKeyUserID), userID)
	return session.Save(c)
}

// updateLoginSuccess updates user statistics after successful login.
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

// accountLockoutAlertKey isolates lockout state per user.
func accountLockoutAlertKey(userID int64) string {
	return fmt.Sprintf("security:account-lockout:user:%d", userID)
}

// updateLoginFailure atomically increments failed login attempts and applies
// the lockout if the threshold is reached. An expired lock resets the counter
// to 1 for the current failure. MySQL evaluates single-table UPDATE
// assignments left-to-right, so locked_until checks the already-incremented
// failed_login_attempts value without a stale read in Go.
//
// The WHERE clause guard skips any update when the row is already actively
// locked. This prevents stale pre-lock requests from extending an existing
// lockout window when concurrent failed logins race past the Go-side check.
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

// isAllowedFrontendURL reports whether the URL is in the allowed origins list.
func (s *Service) isAllowedFrontendURL(urlStr string) bool {
	if urlStr == "" || s.config.AllowedOrigins == "" {
		return false
	}

	return config.IsURLAllowedByOrigin(urlStr, s.config.AllowedOrigins)
}
