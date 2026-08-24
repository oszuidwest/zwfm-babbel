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
		{name: "empty string is allowed", input: new("")},
		{name: "valid 20-char alphanumeric", input: new("21m00Tcm4TlvDq8ikWAM")},
		{name: "valid with hyphen", input: new("voice-abcd1234")},
		{name: "valid with underscore", input: new("voice_abcd1234")},
		{name: "too short", input: new("short"), wantErr: true},
		{name: "too long", input: new(strings.Repeat("a", 65)), wantErr: true},
		{name: "rejects path separator", input: new("voice/../etc"), wantErr: true},
		{name: "rejects query separator", input: new("voice?evil=1"), wantErr: true},
		{name: "rejects whitespace", input: new("voice id 1234"), wantErr: true},
		{name: "rejects url-encoded", input: new("voice%2Fevil"), wantErr: true},
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
