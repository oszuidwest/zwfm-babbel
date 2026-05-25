package api

import "testing"

func TestIsAllowedOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		origin         string
		allowedOrigins string
		want           bool
	}{
		{
			name:           "exact origin",
			origin:         "https://app.example.com",
			allowedOrigins: "https://app.example.com",
			want:           true,
		},
		{
			name:           "configured trailing slash tolerated",
			origin:         "https://app.example.com",
			allowedOrigins: "https://app.example.com/",
			want:           true,
		},
		{
			name:           "multiple origins with whitespace",
			origin:         "http://localhost:3000",
			allowedOrigins: "https://app.example.com, http://localhost:3000",
			want:           true,
		},
		{
			name:           "prefix attack rejected",
			origin:         "https://app.example.com.evil.test",
			allowedOrigins: "https://app.example.com",
			want:           false,
		},
		{
			name:           "userinfo rejected",
			origin:         "https://app.example.com@evil.test",
			allowedOrigins: "https://app.example.com",
			want:           false,
		},
		{
			name:           "allowed path rejected",
			origin:         "https://app.example.com",
			allowedOrigins: "https://app.example.com/callback",
			want:           false,
		},
		{
			name:           "empty origin rejected",
			origin:         "",
			allowedOrigins: "https://app.example.com",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isAllowedOrigin(tt.origin, tt.allowedOrigins); got != tt.want {
				t.Fatalf("isAllowedOrigin(%q, %q) = %v, want %v", tt.origin, tt.allowedOrigins, got, tt.want)
			}
		})
	}
}
