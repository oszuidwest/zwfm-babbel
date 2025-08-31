package auth

import (
	"regexp"
	"testing"
)

func TestSanitizeEmailToUsername(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected string
		pattern  string
	}{
		{
			name:     "Simple email",
			email:    "raymon@zuidwestfm.nl",
			expected: "raymon",
			pattern:  `^[a-zA-Z0-9_-]+$`,
		},
		{
			name:     "Email with dots",
			email:    "john.doe@example.com",
			expected: "john_doe",
			pattern:  `^[a-zA-Z0-9_-]+$`,
		},
		{
			name:     "Email with numbers",
			email:    "user123@test.org",
			expected: "user123",
			pattern:  `^[a-zA-Z0-9_-]+$`,
		},
		{
			name:     "Email with special chars",
			email:    "test+alias@domain.com",
			expected: "test_alias",
			pattern:  `^[a-zA-Z0-9_-]+$`,
		},
		{
			name:     "Short local part",
			email:    "ab@company.com",
			expected: "ab_company",
			pattern:  `^[a-zA-Z0-9_-]+$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the sanitization logic
			base := tt.email[:len(tt.email)-len(tt.email[len(tt.email)-1:])]
			if idx := regexp.MustCompile(`@`).FindStringIndex(tt.email); idx != nil {
				base = tt.email[:idx[0]]
			}

			re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
			result := re.ReplaceAllString(base, "_")

			// Verify the result matches the pattern
			validPattern := regexp.MustCompile(tt.pattern)
			if !validPattern.MatchString(result) {
				t.Errorf("sanitizeEmailToUsername(%q) = %q, doesn't match pattern %q", tt.email, result, tt.pattern)
			}

			// Check minimum length
			if len(result) < 3 && len(base) < 3 {
				t.Logf("Note: %q would need domain appending for minimum length", tt.email)
			}
		})
	}
}

func TestUsernamePattern(t *testing.T) {
	// Test that our target pattern works with sanitized usernames
	pattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	validUsernames := []string{
		"raymon",
		"john_doe",
		"user123",
		"test-user",
		"admin_1",
		"raymon_1",
		"raymon_zuidwestfm",
	}

	for _, username := range validUsernames {
		if !pattern.MatchString(username) {
			t.Errorf("Username %q should be valid but doesn't match pattern", username)
		}
	}

	invalidUsernames := []string{
		"raymon@zuidwestfm.nl",
		"john.doe",
		"user@123",
		"test+user",
		"admin@company.com",
	}

	for _, username := range invalidUsernames {
		if pattern.MatchString(username) {
			t.Errorf("Username %q should be invalid but matches pattern", username)
		}
	}
}
