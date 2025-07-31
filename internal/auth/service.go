package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// Service handles authentication and authorization
type Service struct {
	config   *Config
	db       *sqlx.DB
	enforcer *casbin.Enforcer
	sessions SessionStore
	ginStore interface{} // Store the gin-contrib/sessions store
}

// NewService creates a new authentication service
func NewService(cfg *Config, db *sqlx.DB) (*Service, error) {
	s := &Service{
		config: cfg,
		db:     db,
	}

	// Initialize OIDC if configured
	if cfg.Method == "oidc" || cfg.Method == "both" {
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

// initializeOIDC initializes the OIDC provider
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

// initializeRBAC initializes the role-based access control system
func (s *Service) initializeRBAC() (*casbin.Enforcer, error) {
	// Define RBAC model inline for simplicity and maintenance
	// This approach is intentional to avoid external configuration files
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
			// Log the error but continue - some policies might already exist
			fmt.Printf("Failed to add policy %v: %v\n", p, err)
		}
	}

	return enforcer, nil
}

// SessionMiddleware returns the session middleware
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

// Middleware returns the authentication middleware
func (s *Service) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := s.sessions.Get(c)

		// Check if user is authenticated
		userID := session.Get("user_id")
		if userID == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Load user from database
		var user struct {
			ID          int        `db:"id"`
			Username    string     `db:"username"`
			Role        string     `db:"role"`
			SuspendedAt *time.Time `db:"suspended_at"`
		}

		err := s.db.Get(&user, "SELECT id, username, role, suspended_at FROM users WHERE id = ?", userID)
		if err != nil || user.SuspendedAt != nil {
			session.Delete("user_id")
			_ = session.Save(c)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", user.ID)
		c.Set("username", user.Username)
		c.Set("user_role", user.Role)

		c.Next()
	}
}

// RequirePermission returns middleware that checks for specific permissions
func (s *Service) RequirePermission(obj, act string) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := c.GetString("user_role")

		ok, err := s.enforcer.Enforce(role, obj, act)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Permission check failed"})
			c.Abort()
			return
		}

		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// LocalLogin handles local username/password authentication
func (s *Service) LocalLogin(c *gin.Context, username, password string) error {
	if s.config.Method == "oidc" {
		return fmt.Errorf("local authentication is disabled")
	}

	var user struct {
		ID           int        `db:"id"`
		Username     string     `db:"username"`
		PasswordHash string     `db:"password_hash"`
		Role         string     `db:"role"`
		SuspendedAt  *time.Time `db:"suspended_at"`
	}

	err := s.db.Get(&user, "SELECT id, username, password_hash, role, suspended_at FROM users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("invalid credentials")
	}

	if user.SuspendedAt != nil {
		return fmt.Errorf("account is suspended")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		// Update failed login attempts
		_, _ = s.db.Exec("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?", user.ID)
		return fmt.Errorf("invalid credentials")
	}

	// Update login stats
	_, _ = s.db.Exec(`
		UPDATE users 
		SET last_login_at = NOW(), 
		    login_count = login_count + 1,
		    failed_login_attempts = 0
		WHERE id = ?`, user.ID)

	// Create session
	session := s.sessions.Get(c)
	session.Set("user_id", user.ID)
	session.Set("username", user.Username)
	session.Set("role", user.Role)
	session.Set("auth_method", "local")

	return session.Save(c)
}

// StartOAuthFlow initiates the OAuth authentication flow
func (s *Service) StartOAuthFlow(c *gin.Context) {
	if s.config.Method == "local" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OAuth authentication is disabled"})
		return
	}

	// Generate state for CSRF protection
	state := generateState()
	session := s.sessions.Get(c)
	session.Set("oauth_state", state)
	_ = session.Save(c)

	// Redirect to provider
	url := s.config.OIDC.OAuth2Config.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// FinishOAuthFlow completes the OAuth authentication flow
func (s *Service) FinishOAuthFlow(c *gin.Context) error {
	session := s.sessions.Get(c)

	// Verify state
	state := c.Query("state")
	savedState := session.Get("oauth_state")
	if savedState == nil || state != savedState.(string) {
		return fmt.Errorf("invalid state")
	}
	session.Delete("oauth_state")

	// Exchange code for token
	code := c.Query("code")
	ctx := context.Background()

	token, err := s.config.OIDC.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no id_token in response")
	}

	// Verify ID token
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

	// Find or create user
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}

	var user struct {
		ID          int        `db:"id"`
		SuspendedAt *time.Time `db:"suspended_at"`
	}
	err = s.db.Get(&user, "SELECT id, suspended_at FROM users WHERE username = ?", username)
	if err != nil {
		// Create new user
		result, err := s.db.Exec(`
			INSERT INTO users (username, full_name, email, role, password_hash)
			VALUES (?, ?, ?, 'viewer', '')`,
			username, claims.Name, claims.Email)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get created user ID: %w", err)
		}
		user.ID = int(id)
	} else if user.SuspendedAt != nil {
		return fmt.Errorf("account is suspended")
	}

	// Create session
	session.Set("user_id", user.ID)
	session.Set("username", username)
	session.Set("auth_method", "oidc")

	// Get user role
	var role string
	_ = s.db.Get(&role, "SELECT role FROM users WHERE id = ?", user.ID)
	session.Set("role", role)

	return session.Save(c)
}

// Logout destroys the user session
func (s *Service) Logout(c *gin.Context) {
	session := s.sessions.Get(c)
	session.Clear()
	_ = session.Save(c)
}

// generateState generates a random state string for OAuth2
func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// This should never fail with crypto/rand, but if it does, panic as it's a critical security issue
		panic(fmt.Sprintf("Failed to generate random state: %v", err))
	}
	return base64.URLEncoding.EncodeToString(b)
}
