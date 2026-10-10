package utils

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestDateAfterValidator(t *testing.T) {
	t.Parallel()

	v := validator.New()
	if err := v.RegisterValidation("dateafter", dateAfterValidator); err != nil {
		t.Fatal(err)
	}

	type dates struct {
		StartDate string
		EndDate   string `validate:"dateafter=StartDate"`
	}

	tests := []struct {
		name       string
		start, end string
		wantValid  bool
	}{
		{name: "same day", start: "2026-10-10", end: "2026-10-10", wantValid: true},
		{name: "later day", start: "2026-10-10", end: "2026-10-11", wantValid: true},
		{name: "earlier day", start: "2026-10-10", end: "2026-10-09", wantValid: false},
		{name: "empty end", start: "2026-10-10", end: "", wantValid: true},
		{name: "empty start", start: "", end: "2026-10-09", wantValid: true},
		{name: "invalid end", start: "2026-10-10", end: "10-10-2026", wantValid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := v.Struct(dates{StartDate: tt.start, EndDate: tt.end})
			if (err == nil) != tt.wantValid {
				t.Fatalf("Struct() error = %v, want valid = %v", err, tt.wantValid)
			}
		})
	}
}
