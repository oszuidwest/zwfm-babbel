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
			name: "uppercase scheme and host accepted",
			url:  "HTTPS://APP.EXAMPLE.COM/login",
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
			name: "userinfo authority spoofing the host",
			url:  "https://app.example.com@evil.test/login",
			want: false,
		},
		{
			name: "different port is a different origin",
			url:  "https://app.example.com:8443/login",
			want: false,
		},
		{
			name: "explicit default port matches portless origin",
			url:  "https://app.example.com:443/login",
			want: true,
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

func TestIsAllowedFrontendURLEmptyConfigRejectsAll(t *testing.T) {
	svc := &Service{config: &Config{AllowedOrigins: ""}}

	if svc.isAllowedFrontendURL("https://app.example.com/login") {
		t.Fatal("expected empty AllowedOrigins to reject every URL")
	}
}

func TestIsAllowedFrontendURLToleratesConfiguredTrailingSlash(t *testing.T) {
	svc := &Service{config: &Config{AllowedOrigins: "https://app.example.com/"}}

	if !svc.isAllowedFrontendURL("https://app.example.com/login") {
		t.Fatal("expected a trailing slash on the configured origin to be tolerated")
	}
}
