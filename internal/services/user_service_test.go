package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
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
		wantCode string
	}{
		{
			name:     "valid password",
			password: "Valid123!",
		},
		{
			name:     "too short",
			password: "Val1!",
			wantErr:  "must be at least 8 characters",
			wantCode: apperrors.CodeTooShort,
		},
		{
			name:     "longer than bcrypt accepts",
			password: "Valid1!" + strings.Repeat("é", 33),
			wantErr:  "must be at most 72 bytes",
			wantCode: apperrors.CodeTooLong,
		},
		{
			name:     "missing uppercase",
			password: "valid123!",
			wantErr:  "must contain an uppercase letter",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing lowercase",
			password: "VALID123!",
			wantErr:  "must contain a lowercase letter",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing number",
			password: "ValidPass!",
			wantErr:  "must contain a number",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing special character",
			password: "Valid1234",
			wantErr:  "must contain a special character",
			wantCode: apperrors.CodeInvalidFormat,
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
			var validation *apperrors.ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error type = %T, want *apperrors.ValidationError", err)
			}
			fe := validation.Errors[0]
			if fe.Field != "password" || fe.Code != tt.wantCode || !strings.Contains(fe.Message, tt.wantErr) {
				t.Fatalf("field error = %+v, want password/%s containing %q", fe, tt.wantCode, tt.wantErr)
			}
		})
	}
}
