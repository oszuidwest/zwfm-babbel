package auth

import "fmt"

// Resource represents a protected resource type.
type Resource string

// Resources that can be protected by RBAC.
const (
	// ResourceStations represents radio station resources.
	ResourceStations Resource = "stations"
	// ResourceVoices represents text-to-speech voice resources.
	ResourceVoices Resource = "voices"
	// ResourceStories represents news story resources.
	ResourceStories Resource = "stories"
	// ResourceBulletins represents generated audio bulletin resources.
	ResourceBulletins Resource = "bulletins"
	// ResourceUsers represents user account resources.
	ResourceUsers Resource = "users"
	// ResourceSettingsTTS represents global TTS settings.
	ResourceSettingsTTS Resource = "settings:tts"
	// ResourcePronunciationRules represents ElevenLabs pronunciation rules.
	ResourcePronunciationRules Resource = "pronunciation_rules"
)

// PermissionSet maps API resources to the actions the current subject may perform.
type PermissionSet map[string][]string

// permissionCatalog enumerates every (resource, action) pair the API exposes.
// Wildcard policies carry no resource/action universe of their own, so this
// list must stay in sync with the policies in initializeRBAC.
var permissionCatalog = map[Resource][]Action{
	ResourceStations:           {ActionRead, ActionWrite},
	ResourceVoices:             {ActionRead, ActionWrite},
	ResourceStories:            {ActionRead, ActionWrite},
	ResourceBulletins:          {ActionRead, ActionGenerate},
	ResourceUsers:              {ActionRead, ActionWrite},
	ResourceSettingsTTS:        {ActionRead, ActionWrite},
	ResourcePronunciationRules: {ActionRead, ActionWrite},
}

// EffectivePermissions expands wildcard policies into concrete resource actions.
func (s *Service) EffectivePermissions(subject string) (PermissionSet, error) {
	permissions := PermissionSet{}
	for resource, actions := range permissionCatalog {
		for _, action := range actions {
			allowed, err := s.enforcer.Enforce(subject, string(resource), string(action))
			if err != nil {
				return nil, fmt.Errorf("evaluate %s/%s permission: %w", resource, action, err)
			}
			if allowed {
				permissions[string(resource)] = append(permissions[string(resource)], string(action))
			}
		}
	}
	return permissions, nil
}

// Action represents an operation on a resource.
type Action string

// Actions that can be performed on resources.
const (
	// ActionRead represents read/list operations.
	ActionRead Action = "read"
	// ActionWrite represents create/update/delete operations.
	ActionWrite Action = "write"
	// ActionGenerate represents bulletin generation operations.
	ActionGenerate Action = "generate"
)
