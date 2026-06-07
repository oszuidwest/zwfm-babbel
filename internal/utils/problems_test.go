package utils

import (
	"encoding/json"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
)

func TestValidationProblemUsesAppErrorsValidationError(t *testing.T) {
	errs := []apperrors.ValidationError{{
		Resource: "TTSSettings",
		Field:    "model",
		Message:  "must be one of: eleven_v3, eleven_multilingual_v2",
	}}

	problem := NewValidationProblem("Validation failed", "/tts-settings", errs)

	body, err := json.Marshal(problem)
	if err != nil {
		t.Fatalf("marshal problem: %v", err)
	}

	var payload struct {
		Errors []map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal problem: %v", err)
	}
	if len(payload.Errors) != 1 {
		t.Fatalf("errors len = %d, want 1", len(payload.Errors))
	}
	got := payload.Errors[0]
	if got["field"] != "model" {
		t.Fatalf("field = %q, want model", got["field"])
	}
	if got["message"] != errs[0].Message {
		t.Fatalf("message = %q, want %q", got["message"], errs[0].Message)
	}
	if _, ok := got["resource"]; ok {
		t.Fatalf("resource should be omitted from field-level validation errors: %+v", got)
	}
}
