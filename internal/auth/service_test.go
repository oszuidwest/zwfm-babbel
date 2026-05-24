package auth

import "testing"

func TestIsAllowedFrontendURLRequiresExactOrigin(t *testing.T) {
	svc := &Service{
		config: &Config{
			AllowedOrigins: "https://app.example.com, http://localhost:3000",
		},
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "allowed origin with path",
			url:  "https://app.example.com/login/callback?next=/stories",
			want: true,
		},
		{
			name: "allowed localhost origin",
			url:  "http://localhost:3000/auth/done",
			want: true,
		},
		{
			name: "prefix attack host",
			url:  "https://app.example.com.evil.test/login",
			want: false,
		},
		{
			name: "subdomain is not same origin",
			url:  "https://admin.app.example.com/login",
			want: false,
		},
		{
			name: "scheme must match",
			url:  "http://app.example.com/login",
			want: false,
		},
		{
			name: "relative URL rejected",
			url:  "/login",
			want: false,
		},
		{
			name: "malformed URL rejected",
			url:  "://app.example.com",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := svc.isAllowedFrontendURL(tt.url); got != tt.want {
				t.Fatalf("isAllowedFrontendURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
