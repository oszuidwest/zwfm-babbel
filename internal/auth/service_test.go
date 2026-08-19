package auth

import (
	"maps"
	"slices"
	"testing"
)

func TestEffectivePermissions(t *testing.T) {
	t.Parallel()

	service := &Service{}
	enforcer, err := service.initializeRBAC()
	if err != nil {
		t.Fatalf("initialize RBAC: %v", err)
	}
	service.enforcer = enforcer

	tests := []struct {
		name string
		role string
		want PermissionSet
	}{
		{
			name: "admin wildcard is expanded",
			role: "admin",
			want: PermissionSet{
				"stations":            {"read", "write"},
				"voices":              {"read", "write"},
				"stories":             {"read", "write"},
				"bulletins":           {"read", "generate"},
				"users":               {"read", "write"},
				"settings:tts":        {"read", "write"},
				"pronunciation_rules": {"read", "write"},
			},
		},
		{
			name: "editor",
			role: "editor",
			want: PermissionSet{
				"stations":            {"read", "write"},
				"voices":              {"read", "write"},
				"stories":             {"read", "write"},
				"bulletins":           {"read", "generate"},
				"users":               {"read"},
				"settings:tts":        {"read"},
				"pronunciation_rules": {"read", "write"},
			},
		},
		{
			name: "unknown role has no permissions",
			role: "unknown",
			want: PermissionSet{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := service.EffectivePermissions(tt.role)
			if err != nil {
				t.Fatalf("EffectivePermissions(%q): %v", tt.role, err)
			}
			if !maps.EqualFunc(got, tt.want, slices.Equal) {
				t.Fatalf("EffectivePermissions(%q) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

func TestPermissionCatalogCoversPolicies(t *testing.T) {
	t.Parallel()

	service := &Service{}
	enforcer, err := service.initializeRBAC()
	if err != nil {
		t.Fatalf("initialize RBAC: %v", err)
	}

	policies, err := enforcer.GetPolicy()
	if err != nil {
		t.Fatalf("get policies: %v", err)
	}
	for _, policy := range policies {
		resource, action := policy[1], policy[2]
		if resource == "*" || action == "*" {
			continue
		}
		if !slices.Contains(permissionCatalog[Resource(resource)], Action(action)) {
			t.Errorf("policy %v is missing from permissionCatalog; the session endpoint would never expose it", policy)
		}
	}
}

func TestIsAllowedFrontendURL(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
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
