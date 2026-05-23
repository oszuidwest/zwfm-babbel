package services

import (
	"strings"
	"testing"
)

func TestPasswordPolicyValidate(t *testing.T) {
	t.Parallel()

	policy := PasswordPolicy{
		MinLength:          8,
		RequireUppercase:   true,
		RequireLowercase:   true,
		RequireNumber:      true,
		RequireSpecialChar: true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  string
	}{
		{
			name:     "valid password",
			password: "Valid123!",
		},
		{
			name:     "too short",
			password: "Val1!",
			wantErr:  "must be at least 8 characters",
		},
		{
			name:     "missing uppercase",
			password: "valid123!",
			wantErr:  "must contain an uppercase letter",
		},
		{
			name:     "missing lowercase",
			password: "VALID123!",
			wantErr:  "must contain a lowercase letter",
		},
		{
			name:     "missing number",
			password: "ValidPass!",
			wantErr:  "must contain a number",
		},
		{
			name:     "missing special character",
			password: "Valid1234",
			wantErr:  "must contain a special character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := policy.Validate(tt.password)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
