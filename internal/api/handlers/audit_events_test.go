package handlers

import (
	"errors"
	"net/http"
	"slices"
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

func TestAuditScope(t *testing.T) {
	read := []string{string(auth.ActionRead)}
	tests := []struct {
		name        string
		permissions auth.PermissionSet
		entityTypes []string
		actorNames  bool
	}{
		{name: "stories only", permissions: auth.PermissionSet{"stories": read}, entityTypes: []string{"story"}},
		{name: "settings only", permissions: auth.PermissionSet{"settings:tts": read}, entityTypes: []string{"tts_settings"}},
		{name: "pronunciation only", permissions: auth.PermissionSet{"pronunciation_rules": read}, entityTypes: []string{"pronunciation_rules"}},
		{name: "write without read", permissions: auth.PermissionSet{"stories": {string(auth.ActionWrite)}}},
		{name: "users read alone exposes nothing", permissions: auth.PermissionSet{"users": read}, actorNames: true},
		{
			name:        "all reads",
			permissions: auth.PermissionSet{"stories": read, "settings:tts": read, "pronunciation_rules": read, "users": read},
			entityTypes: []string{"pronunciation_rules", "story", "tts_settings"},
			actorNames:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entityTypes, actorNames := auditScope(tt.permissions)
			if !slices.Equal(entityTypes, tt.entityTypes) || actorNames != tt.actorNames {
				t.Fatalf("auditScope = %v, %t; want %v, %t", entityTypes, actorNames, tt.entityTypes, tt.actorNames)
			}
		})
	}
}
