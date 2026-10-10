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
		wantCode string
	}{
		{
			name:     "valid password",
			password: "Valid123!",
		},
		{
			name:     "too short",
			password: "Val1!",
			wantCode: apperrors.CodeTooShort,
		},
		{
			name:     "longer than bcrypt accepts",
			password: "Valid1!" + strings.Repeat("é", 33),
			wantCode: apperrors.CodeTooLong,
		},
		{
			name:     "exactly 72 bytes",
			password: "Valid1!" + strings.Repeat("é", 32) + "x",
		},
		{
			name:     "missing uppercase",
			password: "valid123!",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing lowercase",
			password: "VALID123!",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing number",
			password: "ValidPass!",
			wantCode: apperrors.CodeInvalidFormat,
		},
		{
			name:     "missing special character",
			password: "Valid1234",
			wantCode: apperrors.CodeInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := policy.Validate(tt.password)
			if tt.wantCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatal("expected validation error")
			}
			var validation *apperrors.ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error type = %T, want *apperrors.ValidationError", err)
			}
			fe := validation.Errors[0]
			if fe.Field != "password" || fe.Code != tt.wantCode || fe.Message == "" {
				t.Fatalf("field error = %+v, want password/%s with a message", fe, tt.wantCode)
			}
		})
	}
}
