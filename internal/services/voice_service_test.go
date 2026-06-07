package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestValidateElevenLabsVoiceID(t *testing.T) {
	tests := []struct {
		name    string
		input   *string
		wantErr bool
	}{
		{name: "nil is allowed", input: nil},
		{name: "empty string is allowed", input: ptr("")},
		{name: "valid 20-char alphanumeric", input: ptr("21m00Tcm4TlvDq8ikWAM")},
		{name: "valid with hyphen", input: ptr("voice-abcd1234")},
		{name: "valid with underscore", input: ptr("voice_abcd1234")},
		{name: "too short", input: ptr("short"), wantErr: true},
		{name: "too long", input: ptr(strings.Repeat("a", 65)), wantErr: true},
		{name: "rejects path separator", input: ptr("voice/../etc"), wantErr: true},
		{name: "rejects query separator", input: ptr("voice?evil=1"), wantErr: true},
		{name: "rejects whitespace", input: ptr("voice id 1234"), wantErr: true},
		{name: "rejects url-encoded", input: ptr("voice%2Fevil"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateElevenLabsVoiceID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				var validation *apperrors.ValidationError
				if !errors.As(err, &validation) {
					t.Fatalf("error type = %T, want *apperrors.ValidationError", err)
				}
				if validation.Field != "elevenlabs_voice_id" {
					t.Fatalf("field = %q, want elevenlabs_voice_id", validation.Field)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
