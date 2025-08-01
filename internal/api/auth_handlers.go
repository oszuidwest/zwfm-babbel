// Package api provides HTTP handlers and routing for the Babbel API.
package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
)

// AuthHandlers handles authentication endpoints
type AuthHandlers struct {
	authService *auth.Service
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authService *auth.Service) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
	}
}

// Login handles local authentication
func (h *AuthHandlers) Login(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := h.authService.LocalLogin(c, req.Username, req.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// StartOAuthFlow initiates the OAuth authentication flow
func (h *AuthHandlers) StartOAuthFlow(c *gin.Context) {
	h.authService.StartOAuthFlow(c)
}

// HandleOAuthCallback processes the OAuth provider callback
func (h *AuthHandlers) HandleOAuthCallback(c *gin.Context) {
	if err := h.authService.FinishOAuthFlow(c); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Redirect to frontend dashboard or return success
	c.Redirect(http.StatusTemporaryRedirect, "/dashboard")
}

// Logout destroys the session
func (h *AuthHandlers) Logout(c *gin.Context) {
	h.authService.Logout(c)
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// GetCurrentUser returns the current user info
func (h *AuthHandlers) GetCurrentUser(c *gin.Context) {
	userID := c.GetInt("user_id")
	username := c.GetString("username")
	role := c.GetString("user_role")

	c.JSON(http.StatusOK, gin.H{
		"id":       userID,
		"username": username,
		"role":     role,
	})
}

// GetAuthConfig returns the authentication configuration
func (h *AuthHandlers) GetAuthConfig(c *gin.Context) {
	response := gin.H{
		"methods": []string{},
	}
	
	// Build available methods array
	if h.authService.IsLocalEnabled() {
		response["methods"] = append(response["methods"].([]string), "local")
	}
	
	if h.authService.IsOAuthEnabled() {
		response["methods"] = append(response["methods"].([]string), "oauth")
		response["oauth_url"] = "/api/v1/session/oauth/start"
	}
	
	c.JSON(http.StatusOK, response)
}
