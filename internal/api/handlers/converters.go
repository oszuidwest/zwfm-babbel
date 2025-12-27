// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

// stringToPtr safely converts a string to a pointer, returning nil for empty strings.
func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
