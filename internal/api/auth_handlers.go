package api

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// AuthHandlers provides HTTP handlers for authentication endpoints including
// local login, OAuth flows, session management, and configuration discovery.
// Handles both username/password and OAuth/OIDC authentication methods.
type AuthHandlers struct {
	authService *auth.Service
	frontendURL string
	handlers    *handlers.Handlers
}

// NewAuthHandlers creates a new authentication handler with the provided services.
// The frontendURL is used for OAuth redirects after successful authentication.
// Returns a configured handler ready for route registration.
func NewAuthHandlers(authService *auth.Service, frontendURL string, h *handlers.Handlers) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
		frontendURL: frontendURL,
		handlers:    h,
	}
}

// Login handles local username/password authentication via JSON POST.
// Validates credentials against the database and creates a secure session.
// Returns 201 Created on success or appropriate error responses for failures.
// Only available when local authentication is enabled in configuration.
func (h *AuthHandlers) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		utils.ProblemBadRequest(c, "Invalid login request format")
		return
	}

	if err := h.authService.LocalLogin(c, req.Username, req.Password); err != nil {
		utils.ProblemAuthentication(c, "Invalid username or password")
		return
	}

	c.JSON(http.StatusCreated, handlers.MessageResponse{Message: "Login successful"})
}

// StartOAuthFlow initiates OAuth/OIDC authentication by redirecting to the provider.
// Generates CSRF protection state and stores frontend redirect URL in session.
// Only available when OAuth authentication is enabled in configuration.
func (h *AuthHandlers) StartOAuthFlow(c *gin.Context) {
	h.authService.StartOAuthFlow(c)
}

// HandleOAuthCallback processes the OAuth provider callback after user authentication.
// Validates CSRF state, exchanges authorization code for tokens, verifies ID token,
// and creates or updates user accounts. Redirects to frontend with success/error status.
// Cleans up temporary session data after processing.
func (h *AuthHandlers) HandleOAuthCallback(c *gin.Context) {
	// Get frontend URL from session or use configured fallback (type-safe)
	session := h.authService.GetSession(c)
	frontendURL, ok := auth.GetSessionFrontendURL(session)
	if !ok || frontendURL == "" {
		if h.frontendURL != "" {
			frontendURL = h.frontendURL
		} else {
			utils.ProblemInternalServer(c, "No frontend URL configured")
			return
		}
	}

	if err := h.authService.FinishOAuthFlow(c); err != nil {
		c.Redirect(http.StatusTemporaryRedirect, frontendURL+"?error="+url.QueryEscape(err.Error()))
		return
	}

	// Clean up OAuth session data (type-safe)
	auth.ClearSessionOAuth(session)
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save session after cleanup: %v", err)
	}

	c.Redirect(http.StatusTemporaryRedirect, frontendURL+"?login=success")
}

// Logout securely destroys the current user session and clears all session data.
// Returns 204 No Content on successful logout. Safe to call multiple times.
func (h *AuthHandlers) Logout(c *gin.Context) {
	if err := h.authService.Logout(c); err != nil {
		utils.ProblemInternalServer(c, "Failed to logout")
		return
	}
	c.Status(http.StatusNoContent)
}

// GetCurrentUser returns the authenticated user's profile information.
// Retrieves user data based on the session and delegates to the standard GetUser handler.
// Requires valid authentication session.
func (h *AuthHandlers) GetCurrentUser(c *gin.Context) {
	// Use type-safe context helper
	userID := auth.MustGetUserID(c)

	// Delegate to GetUser handler
	c.Params = append(c.Params[:0], gin.Param{Key: "id", Value: fmt.Sprintf("%d", userID)})
	h.handlers.GetUser(c)
}

// GetAuthConfig returns the available authentication methods and OIDC URLs.
// Used by frontend applications to discover supported authentication options.
// Returns array of enabled methods ("local", "oidc") and OIDC initiation URL.
func (h *AuthHandlers) GetAuthConfig(c *gin.Context) {
	// Build response using typed struct (compile-time type safety)
	response := handlers.AuthConfigResponse{
		Methods: []string{},
	}

	if h.authService.IsLocalEnabled() {
		response.Methods = append(response.Methods, "local")
	}
	if h.authService.IsOAuthEnabled() {
		response.Methods = append(response.Methods, "oidc")
		response.OAuthURL = "/api/v1/auth/oauth"
	}

	c.JSON(http.StatusOK, response)
}
