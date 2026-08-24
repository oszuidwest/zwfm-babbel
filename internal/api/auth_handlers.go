package api

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// AuthHandlers serves local and OAuth authentication endpoints.
type AuthHandlers struct {
	authService *auth.Service
	frontendURL string
	handlers    *handlers.Handlers
}

// NewAuthHandlers returns authentication handlers using frontendURL as the
// OAuth callback redirect fallback.
func NewAuthHandlers(authService *auth.Service, frontendURL string, h *handlers.Handlers) *AuthHandlers {
	return &AuthHandlers{
		authService: authService,
		frontendURL: frontendURL,
		handlers:    h,
	}
}

// Login authenticates local credentials and starts a session.
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

	utils.CreatedWithMessage(c, "Login successful")
}

// StartOAuthFlow redirects to the configured provider.
func (h *AuthHandlers) StartOAuthFlow(c *gin.Context) {
	h.authService.StartOAuthFlow(c)
}

// HandleOAuthCallback completes authentication and redirects to the frontend.
func (h *AuthHandlers) HandleOAuthCallback(c *gin.Context) {
	session := h.authService.Session(c)
	frontendURL, ok := auth.SessionFrontendURL(session)
	if !ok || frontendURL == "" {
		if h.frontendURL != "" {
			frontendURL = h.frontendURL
		} else {
			utils.ProblemInternalServer(c, "No frontend URL configured")
			return
		}
	}

	if err := h.authService.FinishOAuthFlow(c); err != nil {
		c.Redirect(http.StatusSeeOther, frontendURL+"?error="+url.QueryEscape(err.Error()))
		return
	}

	auth.ClearSessionOAuth(session)
	if err := session.Save(c); err != nil {
		logger.Error("Failed to save session after cleanup", "error", err)
	}

	c.Redirect(http.StatusSeeOther, frontendURL+"?login=success")
}

// Logout clears the current session. It is safe to call repeatedly.
func (h *AuthHandlers) Logout(c *gin.Context) {
	if err := h.authService.Logout(c); err != nil {
		utils.ProblemInternalServer(c, "Failed to logout")
		return
	}
	c.Status(http.StatusNoContent)
}

// GetCurrentUser returns the authenticated user's profile augmented with the
// effective permissions for their role.
func (h *AuthHandlers) GetCurrentUser(c *gin.Context) {
	userID, ok := auth.UserID(c)
	if !ok {
		utils.ProblemAuthentication(c, "Not authenticated")
		return
	}

	role, ok := auth.UserRole(c)
	if !ok {
		utils.ProblemAuthentication(c, "Invalid session")
		return
	}
	permissions, err := h.authService.EffectivePermissions(role)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to resolve permissions")
		return
	}

	h.handlers.RespondWithCurrentUser(c, userID, permissions)
}

// GetAuthConfig reports the enabled frontend login methods.
// OAuth-enabled deployments include the local initiation URL for the OIDC flow.
func (h *AuthHandlers) GetAuthConfig(c *gin.Context) {
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

	utils.Success(c, response)
}
