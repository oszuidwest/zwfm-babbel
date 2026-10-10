package utils

import (
	"reflect"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
)

func TestParseDateField(t *testing.T) {
	t.Parallel()

	ptr := func(s string) *string { return &s }
	localDate := time.Date(2026, 10, 10, 0, 0, 0, 0, time.Local)
	zoned := time.Date(2026, 10, 10, 23, 30, 0, 0, time.FixedZone("UTC+14", 14*3600))
	var nilString *string
	var nilTime *time.Time
	doublePtr := ptr("2026-10-10")

	tests := []struct {
		name      string
		field     reflect.Value
		want      dateParseResult
		supported bool
	}{
		{name: "invalid value", field: reflect.Value{}, want: dateParseResult{IsEmpty: true}, supported: true},
		{name: "nil string pointer", field: reflect.ValueOf(nilString), want: dateParseResult{IsEmpty: true}, supported: true},
		{name: "nil time pointer", field: reflect.ValueOf(nilTime), want: dateParseResult{IsEmpty: true}, supported: true},
		{name: "empty string", field: reflect.ValueOf(""), want: dateParseResult{IsEmpty: true}, supported: true},
		{name: "empty string pointer", field: reflect.ValueOf(ptr("")), want: dateParseResult{IsEmpty: true}, supported: true},
		{name: "date-only string", field: reflect.ValueOf("2026-10-10"), want: dateParseResult{Time: localDate}, supported: true},
		{name: "date-only string pointer", field: reflect.ValueOf(ptr("2026-10-10")), want: dateParseResult{Time: localDate}, supported: true},
		{name: "RFC 3339 string", field: reflect.ValueOf("2026-10-10T00:00:00Z"), want: dateParseResult{FailValidation: true}, supported: true},
		{name: "invalid date string", field: reflect.ValueOf("2026-02-30"), want: dateParseResult{FailValidation: true}, supported: true},
		{name: "time keeps its zone", field: reflect.ValueOf(zoned), want: dateParseResult{Time: zoned}, supported: true},
		{name: "non-nil time pointer", field: reflect.ValueOf(&zoned), supported: false},
		{name: "pointer to string pointer", field: reflect.ValueOf(&doublePtr), supported: false},
		{name: "int", field: reflect.ValueOf(20261010), supported: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, supported := parseDateField(tt.field)
			if supported != tt.supported {
				t.Fatalf("supported = %v, want %v", supported, tt.supported)
			}
			if got.IsEmpty != tt.want.IsEmpty || got.FailValidation != tt.want.FailValidation {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			if !got.Time.Equal(tt.want.Time) || got.Time.Location().String() != tt.want.Time.Location().String() {
				t.Fatalf("time = %v, want %v", got.Time, tt.want.Time)
			}
		})
	}
}

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
