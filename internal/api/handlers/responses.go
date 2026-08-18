package handlers

import (
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// AuthConfigResponse represents the authentication configuration response.
type AuthConfigResponse struct {
	Methods  []string `json:"methods"`
	OAuthURL string   `json:"oauth_url,omitempty"`
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// CurrentSessionResponse augments the authenticated user with server-derived permissions.
type CurrentSessionResponse struct {
	*models.User
	Permissions auth.PermissionSet `json:"permissions"`
}
