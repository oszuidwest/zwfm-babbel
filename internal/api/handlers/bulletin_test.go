package handlers

import "testing"

func TestAcceptsJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{name: "omitted", accept: "", want: true},
		{name: "JSON", accept: "application/json", want: true},
		{name: "JSON with parameters", accept: "application/json; charset=utf-8", want: true},
		{name: "wildcard", accept: "*/*", want: true},
		{name: "JSON among alternatives", accept: "audio/wav, application/json", want: true},
		{name: "audio only", accept: "audio/wav", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := acceptsJSON(tt.accept); got != tt.want {
				t.Fatalf("acceptsJSON(%q) = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}
