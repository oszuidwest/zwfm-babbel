package config

import "testing"

func TestNormalizeOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "canonical origin", raw: "https://app.example.com", want: "https://app.example.com"},
		{name: "uppercase origin", raw: "HTTPS://APP.EXAMPLE.COM", want: "https://app.example.com"},
		{name: "port preserved", raw: "http://LOCALHOST:3000", want: "http://localhost:3000"},
		{name: "single trailing slash tolerated", raw: "https://app.example.com/", want: "https://app.example.com"},
		{name: "surrounding whitespace trimmed", raw: " https://app.example.com ", want: "https://app.example.com"},
		{name: "empty rejected", raw: "", wantErr: "must not be empty"},
		{name: "missing scheme rejected", raw: "app.example.com", wantErr: "missing scheme"},
		{name: "missing host rejected", raw: "https://", wantErr: "missing host"},
		{name: "userinfo rejected", raw: "https://app.example.com@evil.test", wantErr: "user information"},
		{name: "path rejected", raw: "https://app.example.com/callback", wantErr: "without path, query, or fragment"},
		{name: "multiple slashes rejected", raw: "https://app.example.com//", wantErr: "without path, query, or fragment"},
		{name: "query rejected", raw: "https://app.example.com?next=/x", wantErr: "without path, query, or fragment"},
		{name: "empty query marker rejected", raw: "https://app.example.com?", wantErr: "without path, query, or fragment"},
		{name: "fragment rejected", raw: "https://app.example.com#frag", wantErr: "without path, query, or fragment"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeOrigin(tt.raw)
			assertOriginResult(t, got, err, tt.want, tt.wantErr)
		})
	}
}

func TestOriginFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr string
	}{
		{name: "bare origin", raw: "https://app.example.com", want: "https://app.example.com"},
		{name: "path and query allowed", raw: "https://app.example.com/login?next=/stories", want: "https://app.example.com"},
		{name: "fragment allowed", raw: "https://app.example.com/login#done", want: "https://app.example.com"},
		{name: "port preserved", raw: "http://localhost:3000/auth/done", want: "http://localhost:3000"},
		{name: "uppercase canonicalized", raw: "HTTPS://APP.EXAMPLE.COM/login", want: "https://app.example.com"},
		{name: "relative URL rejected", raw: "/login", wantErr: "missing scheme"},
		{name: "missing host rejected", raw: "https:///login", wantErr: "missing host"},
		{name: "userinfo rejected", raw: "https://app.example.com@evil.test/login", wantErr: "user information"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := originFromURL(tt.raw)
			assertOriginResult(t, got, err, tt.want, tt.wantErr)
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		origin         string
		allowedOrigins string
		want           bool
	}{
		{name: "exact origin", origin: "https://app.example.com", allowedOrigins: "https://app.example.com", want: true},
		{name: "configured trailing slash tolerated", origin: "https://app.example.com", allowedOrigins: "https://app.example.com/", want: true},
		{name: "multiple origins with whitespace", origin: "http://localhost:3000", allowedOrigins: "https://app.example.com, http://localhost:3000", want: true},
		{name: "prefix attack rejected", origin: "https://app.example.com.evil.test", allowedOrigins: "https://app.example.com", want: false},
		{name: "userinfo rejected", origin: "https://app.example.com@evil.test", allowedOrigins: "https://app.example.com", want: false},
		{name: "allowed path rejected", origin: "https://app.example.com", allowedOrigins: "https://app.example.com/callback", want: false},
		{name: "empty origin rejected", origin: "", allowedOrigins: "https://app.example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsOriginAllowed(tt.origin, tt.allowedOrigins); got != tt.want {
				t.Fatalf("IsOriginAllowed(%q, %q) = %v, want %v", tt.origin, tt.allowedOrigins, got, tt.want)
			}
		})
	}
}

func TestIsURLAllowedByOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		rawURL         string
		allowedOrigins string
		want           bool
	}{
		{name: "full URL with path allowed", rawURL: "https://app.example.com/login?next=/stories", allowedOrigins: "https://app.example.com", want: true},
		{name: "uppercase URL canonicalized", rawURL: "HTTPS://APP.EXAMPLE.COM/login", allowedOrigins: "https://app.example.com", want: true},
		{name: "different port rejected", rawURL: "https://app.example.com:8443/login", allowedOrigins: "https://app.example.com", want: false},
		{name: "explicit default port rejected", rawURL: "https://app.example.com:443/login", allowedOrigins: "https://app.example.com", want: false},
		{name: "relative URL rejected", rawURL: "/login", allowedOrigins: "https://app.example.com", want: false},
		{name: "userinfo rejected", rawURL: "https://app.example.com@evil.test/login", allowedOrigins: "https://evil.test", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := IsURLAllowedByOrigin(tt.rawURL, tt.allowedOrigins); got != tt.want {
				t.Fatalf("IsURLAllowedByOrigin(%q, %q) = %v, want %v", tt.rawURL, tt.allowedOrigins, got, tt.want)
			}
		})
	}
}

func assertOriginResult(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()

	if wantErr != "" {
		assertErrorContains(t, err, wantErr)
		return
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
