// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

// MessageResponse represents a simple message response.
type MessageResponse struct {
	Message string `json:"message"`
}

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

// PaginationMeta contains pagination metadata for list responses.
type PaginationMeta struct {
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}

// PaginatedResponse is a generic wrapper for paginated responses.
type PaginatedResponse[T any] struct {
	Data       []T            `json:"data"`
	Pagination PaginationMeta `json:"pagination"`
}
