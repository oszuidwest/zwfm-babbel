// Package auth provides authentication and authorization services for the Babbel API.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// Service handles authentication and authorization.
type Service struct {
	config   *Config
	db       *sqlx.DB
	enforcer *casbin.Enforcer
	sessions SessionStore
	ginStore interface{}
}

// IsLocalEnabled returns true if local authentication is enabled.
func (s *Service) IsLocalEnabled() bool {
	return s.config.Method.SupportsLocal()
}

// IsOAuthEnabled returns true if OAuth/OIDC authentication is enabled.
func (s *Service) IsOAuthEnabled() bool {
	return s.config.Method.SupportsOIDC()
}

// NewService creates a new authentication service.
func NewService(cfg *Config, db *sqlx.DB) (*Service, error) {
	s := &Service{
		config: cfg,
		db:     db,
	}

	// Initialize OIDC if configured
	if cfg.Method.SupportsOIDC() {
		if err := s.initializeOIDC(); err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC: %w", err)
		}
	}

	// Initialize session store
	store, ginStore, err := NewGinSessionStore(cfg.Session)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize session store: %w", err)
	}
	s.sessions = store
	s.ginStore = ginStore

	// Initialize Casbin for RBAC
	enforcer, err := s.initializeRBAC()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Casbin: %w", err)
	}
	s.enforcer = enforcer

	return s, nil
}

// initializeOIDC configures the OIDC provider for OAuth authentication.
func (s *Service) initializeOIDC() error {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, s.config.OIDC.ProviderURL)
	if err != nil {
		return err
	}

	s.config.OIDC.Provider = provider

	// Configure OAuth2
	oauth2Config := &oauth2.Config{
		ClientID:     s.config.OIDC.ClientID,
		ClientSecret: s.config.OIDC.ClientSecret,
		RedirectURL:  s.config.OIDC.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       s.config.OIDC.Scopes,
	}

	// Override endpoints if specified
	if s.config.OIDC.AuthURL != "" {
		oauth2Config.Endpoint.AuthURL = s.config.OIDC.AuthURL
	}
	if s.config.OIDC.TokenURL != "" {
		oauth2Config.Endpoint.TokenURL = s.config.OIDC.TokenURL
	}

	s.config.OIDC.OAuth2Config = oauth2Config

	return nil
}

// initializeRBAC sets up role-based access control using Casbin.
func (s *Service) initializeRBAC() (*casbin.Enforcer, error) {
	// Define RBAC model inline
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

	// Create a database adapter for Casbin
	adapter := NewCasbinAdapter(s.db)

	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, err
	}

	// Load initial policies
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, err
	}

	// Define default policies
	policies := [][]string{
		// Admins can do everything
		{"admin", "*", "*"},

		// Editors can manage content
		{"editor", "stations", "read"},
		{"editor", "stations", "write"},
		{"editor", "voices", "read"},
		{"editor", "voices", "write"},
		{"editor", "stories", "read"},
		{"editor", "stories", "write"},
		{"editor", "bulletins", "generate"},
		{"editor", "bulletins", "read"},
		{"editor", "broadcasts", "read"},
		{"editor", "users", "read"}, // Can view users

		// Viewers can only read
		{"viewer", "stations", "read"},
		{"viewer", "voices", "read"},
		{"viewer", "stories", "read"},
		{"viewer", "bulletins", "read"},
		{"viewer", "broadcasts", "read"},

		// User management is admin only
		{"admin", "users", "read"},
		{"admin", "users", "write"},
	}

	for _, p := range policies {
		if _, err := enforcer.AddPolicy(p); err != nil {
			// Some policies might already exist
			logger.Warn("Failed to add policy %v: %v", p, err)
		}
	}

	return enforcer, nil
}

// sanitizeEmailToUsername converts an email address to a valid username.
// It takes the local part (before @) and replaces invalid characters with underscores.
// Example: raymon@zuidwestfm.nl → raymon
func (s *Service) sanitizeEmailToUsername(email string) string {
	// Take the part before @ (local part of email)
	base, _, _ := strings.Cut(email, "@")

	// Replace any character that's not alphanumeric, underscore, or hyphen with underscore
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	username := re.ReplaceAllString(base, "_")

	// Ensure the username is not empty and meets minimum length requirement
	if len(username) < 3 {
		// If too short, append part of the domain
		if _, domainStr, found := strings.Cut(email, "@"); found {
			domainPart, _, _ := strings.Cut(domainStr, ".")
			domainPart = re.ReplaceAllString(domainPart, "_")
			username = username + "_" + domainPart
		}
	}

	// Truncate if too long (max 100 characters)
	if len(username) > 100 {
		username = username[:100]
	}

	// Ensure uniqueness
	return s.ensureUniqueUsername(username)
}

// ensureUniqueUsername checks if a username exists and adds a numeric suffix if needed.
// It returns a unique username, appending _1, _2, etc. until an available username is found.
func (s *Service) ensureUniqueUsername(baseUsername string) string {
	username := baseUsername
	counter := 1
	ctx := context.Background()

	for {
		var exists bool
		err := s.db.GetContext(ctx, &exists, "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username)
		if err != nil {
			// On error, assume it might exist and try with suffix
			logger.Warn("Database error checking username uniqueness, trying next: %v", err)
			username = fmt.Sprintf("%s_%d", baseUsername, counter)
			counter++
			if counter > 100 {
				// Fallback to timestamp-based username to avoid infinite loop
				username = fmt.Sprintf("%s_%d", baseUsername, time.Now().Unix())
				break
			}
			continue
		}

		if !exists {
			break
		}

		// Username exists, try with numeric suffix
		username = fmt.Sprintf("%s_%d", baseUsername, counter)
		counter++

		// Ensure we don't exceed the max length (100 characters)
		if len(username) > 100 {
			// Truncate base and add suffix
			maxBaseLen := 100 - len(fmt.Sprintf("_%d", counter))
			if maxBaseLen < 1 {
				maxBaseLen = 90
			}
			truncatedBase := baseUsername
			if len(truncatedBase) > maxBaseLen {
				truncatedBase = truncatedBase[:maxBaseLen]
			}
			username = fmt.Sprintf("%s_%d", truncatedBase, counter)
		}
	}

	return username
}

// SessionMiddleware returns the Gin middleware for session management.
func (s *Service) SessionMiddleware() gin.HandlerFunc {
	if _, ok := s.sessions.(*GinSessionStore); ok {
		// Use gin-contrib/sessions middleware
		if store, ok := s.ginStore.(sessions.Store); ok {
			return CreateSessionMiddleware(s.config.Session.CookieName, store)
		}
	}
	// Default pass-through
	return func(c *gin.Context) {
		c.Next()
	}
}

// Middleware returns the Gin middleware for authentication enforcement.
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := s.sessions.Get(c)

		// Check if user is authenticated (type-safe)
		userID, ok := GetSessionUserID(session)
		if !ok {
			utils.ProblemAuthentication(c, "Authentication required")
			c.Abort()
			return
		}

		// Load user from database
		var user struct {
			ID          int64      `db:"id"`
			Username    string     `db:"username"`
			Role        string     `db:"role"`
			SuspendedAt *time.Time `db:"suspended_at"`
		}

		err := s.db.GetContext(c.Request.Context(), &user, "SELECT id, username, role, suspended_at FROM users WHERE id = ?", userID)
		if err != nil || user.SuspendedAt != nil {
			session.Delete(string(SessKeyUserID))
			if err := session.Save(c); err != nil {
				logger.Error("Failed to save session during cleanup: %v", err)
			}
			utils.ProblemAuthentication(c, "Invalid session")
			c.Abort()
			return
		}

		// Set user info in context (type-safe)
		SetUserContext(c, UserContext{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
		})

		c.Next()
	}
}

// RequirePermission returns middleware that enforces role-based access control.
func (s *Service) RequirePermission(obj Resource, act Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		role, roleOk := GetUserRole(c)
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
		ID           int64      `db:"id"`
		Username     string     `db:"username"`
		PasswordHash string     `db:"password_hash"`
		Role         string     `db:"role"`
		SuspendedAt  *time.Time `db:"suspended_at"`
	}

	ctx := c.Request.Context()
	err := s.db.GetContext(ctx, &user, "SELECT id, username, password_hash, role, suspended_at FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}

	if user.SuspendedAt != nil {
		return fmt.Errorf("account is suspended")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Increment failed login attempt counter
		if updateErr := s.updateLoginFailure(ctx, user.ID); updateErr != nil {
			logger.Error("Failed to update login failure stats: %v", updateErr)
		}
		return fmt.Errorf("invalid credentials")
	}

	// Reset failed attempts and update login statistics
	if err := s.updateLoginSuccess(ctx, user.ID); err != nil {
		logger.Error("Failed to update login success stats: %v", err)
	}

	// Create session for authenticated user
	return s.CreateSession(c, user.ID, user.Username, user.Role, "local")
}

// StartOAuthFlow initiates the OAuth/OIDC authentication process.
func (s *Service) StartOAuthFlow(c *gin.Context) {
	if !s.config.Method.SupportsOIDC() {
		utils.ProblemBadRequest(c, "OAuth authentication is disabled")
		return
	}

	// Generate state for CSRF protection (type-safe error handling)
	state, err := generateState()
	if err != nil {
		logger.Error("Failed to generate OAuth state: %v", err)
		utils.ProblemInternalServer(c, "Failed to initiate OAuth flow")
		return
	}

	session := s.sessions.Get(c)
	SetSessionOAuthState(session, state)

	// Store frontend URL for later redirect (type-safe)
	frontendURL := c.Query("frontend_url")
	if frontendURL != "" {
		SetSessionFrontendURL(session, frontendURL)
	}
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save OAuth session: %v", err)
		utils.ProblemInternalServer(c, "Session error")
		return
	}

	// Redirect to provider
	url := s.config.OIDC.OAuth2Config.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// FinishOAuthFlow completes the OAuth authentication process.
func (s *Service) FinishOAuthFlow(c *gin.Context) error {
	session := s.sessions.Get(c)

	// Verify state (type-safe)
	state := c.Query("state")
	savedStateStr, ok := GetSessionOAuthState(session)
	if !ok || state != savedStateStr {
		return fmt.Errorf("invalid state")
	}
	session.Delete(string(SessKeyOAuthState))

	// Exchange code for token
	code := c.Query("code")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	token, err := s.config.OIDC.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no id_token in response")
	}

	verifier := s.config.OIDC.Provider.Verifier(&oidc.Config{
		ClientID: s.config.OIDC.ClientID,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("failed to parse claims: %w", err)
	}

	// Find or create user based on OAuth claims
	user, err := s.findOrCreateOAuthUser(c.Request.Context(), claims.Email, claims.Name, claims.PreferredUsername)
	if err != nil {
		return err
	}

	// Setup session for authenticated OAuth user
	return s.setupOAuthSession(c, user)
}

// oauthUser represents the minimal user information needed for OAuth session setup.
type oauthUser struct {
	ID       int64
	Username string
}

// findOrCreateOAuthUser finds an existing user by email or creates a new one.
// Returns the user ID and username, or an error if the account is suspended or creation fails.
func (s *Service) findOrCreateOAuthUser(ctx context.Context, email, fullName, preferredUsername string) (*oauthUser, error) {
	var existingUser struct {
		ID          int64      `db:"id"`
		Username    string     `db:"username"`
		SuspendedAt *time.Time `db:"suspended_at"`
	}

	// Try to find user by email first
	err := s.db.GetContext(ctx, &existingUser, "SELECT id, username, suspended_at FROM users WHERE email = ?", email)
	if err == nil {
		// User exists with this email
		if existingUser.SuspendedAt != nil {
			return nil, fmt.Errorf("account is suspended")
		}
		return &oauthUser{
			ID:       existingUser.ID,
			Username: existingUser.Username,
		}, nil
	}

	// No existing user with this email, create new user
	username := s.determineOAuthUsername(preferredUsername, email)

	result, err := s.db.ExecContext(ctx, `
		INSERT INTO users (username, full_name, email, role, password_hash, last_login_at, login_count)
		VALUES (?, ?, ?, 'viewer', '', NOW(), 1)`,
		username, fullName, email)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get created user ID: %w", err)
	}

	return &oauthUser{
		ID:       id, // Already int64, no cast needed
		Username: username,
	}, nil
}

// determineOAuthUsername determines the best username from OAuth claims.
// Prefers preferredUsername if valid, otherwise sanitizes the email.
func (s *Service) determineOAuthUsername(preferredUsername, email string) string {
	username := preferredUsername
	if username == "" {
		return s.sanitizeEmailToUsername(email)
	}

	// Sanitize if preferredUsername contains invalid characters
	if strings.Contains(username, "@") || strings.Contains(username, ".") {
		return s.sanitizeEmailToUsername(username)
	}

	return username
}

// setupOAuthSession creates a session for an OAuth-authenticated user.
// Updates login statistics and retrieves the user's current role from the database.
func (s *Service) setupOAuthSession(c *gin.Context, user *oauthUser) error {
	ctx := c.Request.Context()

	// Reset failed attempts and update login statistics
	if err := s.updateLoginSuccess(ctx, user.ID); err != nil {
		logger.Error("Failed to update login success stats: %v", err)
	}

	// Get the user's actual role from database
	var role string
	if err := s.db.GetContext(ctx, &role, "SELECT role FROM users WHERE id = ?", user.ID); err != nil {
		logger.Error("SECURITY: Failed to get user role for user %d, defaulting to viewer: %v", user.ID, err)
		role = "viewer"
	}

	// Create session with user credentials
	if err := s.CreateSession(c, user.ID, user.Username, role, "oidc"); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSession retrieves the current session for the request context.
func (s *Service) GetSession(c *gin.Context) Session {
	return s.sessions.Get(c)
}

// Logout destroys the user session.
func (s *Service) Logout(c *gin.Context) {
	session := s.sessions.Get(c)
	session.Clear()
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save session during logout: %v", err)
	}
}

// CreateSession creates a new session for the authenticated user.
// It stores the user ID, username, role, and authentication method in the session.
// Returns an error if the session cannot be saved.
func (s *Service) CreateSession(c *gin.Context, userID int64, username string, role string, authMethod string) error {
	session := s.sessions.Get(c)
	// Use type-safe session helpers
	SetSessionAuth(session, SessionData{
		UserID:     userID,
		Username:   username,
		Role:       role,
		AuthMethod: authMethod,
	})
	return session.Save(c)
}

// updateLoginSuccess updates user statistics after successful login.
// It resets failed login attempts and increments the login count.
// Returns an error if the database update fails.
func (s *Service) updateLoginSuccess(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET last_login_at = NOW(),
		    login_count = login_count + 1,
		    failed_login_attempts = 0
		WHERE id = ?`, userID)
	if err != nil {
		logger.Error("Failed to update login stats: %v", err)
	}
	return err
}

// updateLoginFailure increments failed login attempts for a user.
// Returns an error if the database update fails.
func (s *Service) updateLoginFailure(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1
		WHERE id = ?`, userID)
	if err != nil {
		logger.Error("Failed to update failed login attempts: %v", err)
	}
	return err
}

// generateState generates a cryptographically secure random state parameter for OAuth2 CSRF protection.
// Returns an error if the random number generator fails (extremely rare but possible).
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
