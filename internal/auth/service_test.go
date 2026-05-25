package auth

import "testing"

func TestIsAllowedFrontendURL(t *testing.T) {
	const defaultOrigins = "https://app.example.com, http://localhost:3000"

	// origins is a *string so the table can distinguish "use default" (nil) from
	// "explicitly empty" (pointer to ""), since both are valid scenarios.
	emptyOrigins := ""
	trailingSlashOrigins := "https://app.example.com/"

	tests := []struct {
		name    string
		origins *string
		url     string
		want    bool
	}{
		{name: "allowed origin with path", url: "https://app.example.com/login/callback?next=/stories", want: true},
		{name: "allowed localhost origin", url: "http://localhost:3000/auth/done", want: true},
		{name: "uppercase scheme and host accepted", url: "HTTPS://APP.EXAMPLE.COM/login", want: true},
		{name: "prefix attack host", url: "https://app.example.com.evil.test/login", want: false},
		{name: "subdomain is not same origin", url: "https://admin.app.example.com/login", want: false},
		{name: "scheme must match", url: "http://app.example.com/login", want: false},
		{name: "userinfo authority spoofing the host", url: "https://app.example.com@evil.test/login", want: false},
		{name: "different port is a different origin", url: "https://app.example.com:8443/login", want: false},
		{name: "explicit default port matches portless origin", url: "https://app.example.com:443/login", want: true},
		{name: "relative URL rejected", url: "/login", want: false},
		{name: "malformed URL rejected", url: "://app.example.com", want: false},
		{name: "empty config rejects all", origins: &emptyOrigins, url: "https://app.example.com/login", want: false},
		{name: "configured trailing slash tolerated", origins: &trailingSlashOrigins, url: "https://app.example.com/login", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origins := defaultOrigins
			if tt.origins != nil {
				origins = *tt.origins
			}
			svc := &Service{config: &Config{AllowedOrigins: origins}}
			if got := svc.isAllowedFrontendURL(tt.url); got != tt.want {
				t.Fatalf("isAllowedFrontendURL(%q) with origins %q = %v, want %v", tt.url, origins, got, tt.want)
			}
		})
	}
}
