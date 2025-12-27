// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

// stringToPtr safely converts a string to a pointer, returning nil for empty strings.
// This avoids the unsafe pattern of taking a pointer to a local variable.
func stringToPtr(s string) *string {
	if s == "" {
		return nil
	}
	// Create a new string in heap by copying value
	copy := s
	return &copy
}
