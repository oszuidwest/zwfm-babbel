package handlers

import (
	"errors"
	"net/http"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/auth"
)

func TestAuditEventsAccessErrors(t *testing.T) {
	tests := []struct {
		name          string
		authenticated bool
		permissionErr error
		status        int
	}{
		{name: "unauthenticated", status: http.StatusUnauthorized},
		{name: "no read permission", authenticated: true, status: http.StatusForbidden},
		{name: "permission evaluation failure", authenticated: true, permissionErr: errors.New("unavailable"), status: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuditEventsHandler(nil, func(string) (auth.PermissionSet, error) {
				if !tt.authenticated {
					t.Fatal("evaluated permissions without authentication")
				}
				return auth.PermissionSet{}, tt.permissionErr
			})
			c, response := newProblemContext(t)
			if tt.authenticated {
				auth.SetUserContext(c, auth.UserContext{UserID: 307, Role: "viewer"})
			}
			handler.List(c)
			if response.Code != tt.status || response.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("response = %d %s, want problem %d", response.Code, response.Body, tt.status)
			}
		})
	}
}
