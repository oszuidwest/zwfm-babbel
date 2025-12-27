// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

// stringToPtr safely converts a string to a pointer, returning nil for empty strings.
// This avoids the unsafe pattern of taking a pointer to a local variable.
func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	// Create a local copy to avoid returning a pointer to the parameter.
	copy := s
	return &copy
}
