package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDateScan(t *testing.T) {
	tests := []struct {
		name  string
		value time.Time
		want  string
	}{
		{name: "positive offset", value: time.Date(2026, 9, 26, 0, 0, 0, 0, time.FixedZone("CEST", 2*60*60)), want: "2026-09-26"},
		{name: "negative offset", value: time.Date(2026, 9, 26, 23, 0, 0, 0, time.FixedZone("west", -7*60*60)), want: "2026-09-26"},
		{name: "leap day", value: time.Date(2024, 2, 29, 0, 0, 0, 0, time.Local), want: "2024-02-29"},
		{name: "DST start", value: time.Date(2026, 3, 29, 0, 0, 0, 0, time.Local), want: "2026-03-29"},
		{name: "DST end", value: time.Date(2026, 10, 25, 0, 0, 0, 0, time.Local), want: "2026-10-25"},
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
	var date Date
	if err := date.Scan("2026-09-26"); err == nil {
		t.Error("Scan(string) succeeded, want error")
	}
}
