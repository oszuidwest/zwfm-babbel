package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDateRoundTrip(t *testing.T) {
	for _, value := range []string{"2026-09-26", "2024-02-29", "2026-03-29", "2026-10-25"} {
		t.Run(value, func(t *testing.T) {
			var date Date
			if err := json.Unmarshal([]byte(`"`+value+`"`), &date); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(date)
			if err != nil || string(data) != `"`+value+`"` {
				t.Fatalf("Marshal = %s, %v; want %q", data, err, value)
			}
			dbValue, err := date.Value()
			if err != nil || dbValue != value {
				t.Fatalf("Value = %v, %v; want %q", dbValue, err, value)
			}
		})
	}
}

func TestDateUnmarshalRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{`"2026-02-29"`, `"2026-9-26"`, `"2026-09-26T00:00:00+02:00"`, `""`, `null`, `123`, `{}`} {
		t.Run(value, func(t *testing.T) {
			date := Date(time.Date(2026, 9, 26, 0, 0, 0, 0, time.Local))
			original := date
			if err := json.Unmarshal([]byte(value), &date); err == nil {
				t.Fatal("expected an invalid date error")
			}
			if date != original {
				t.Fatal("invalid input changed the date")
			}
		})
	}
}

func TestDateScan(t *testing.T) {
	localMidnight := time.Date(2026, 9, 26, 0, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "time with positive offset", value: localMidnight, want: "2026-09-26"},
		{name: "time with negative offset", value: time.Date(2026, 9, 26, 23, 0, 0, 0, time.FixedZone("west", -7*60*60)), want: "2026-09-26"},
		{name: "string", value: "2026-09-26", want: "2026-09-26"},
		{name: "bytes", value: []byte("2026-09-26"), want: "2026-09-26"},
		{name: "null", value: nil, want: "0001-01-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var date Date
			if err := date.Scan(tt.value); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(date)
			if err != nil || string(data) != `"`+tt.want+`"` {
				t.Fatalf("Marshal = %s, %v; want %q", data, err, tt.want)
			}
			value, err := date.Value()
			if err != nil || value != tt.want {
				t.Fatalf("Value = %v, %v; want %q", value, err, tt.want)
			}
		})
	}
	for _, value := range []any{123, "2026-02-30", []byte("not a date")} {
		var date Date
		if err := date.Scan(value); err == nil {
			t.Errorf("Scan(%v) succeeded, want error", value)
		}
	}
}
