package handlers

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
