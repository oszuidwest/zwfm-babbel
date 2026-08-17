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

var permissionCatalog = []struct {
	resource Resource
	actions  []Action
}{
	{resource: ResourceStations, actions: []Action{ActionRead, ActionWrite}},
	{resource: ResourceVoices, actions: []Action{ActionRead, ActionWrite}},
	{resource: ResourceStories, actions: []Action{ActionRead, ActionWrite}},
	{resource: ResourceBulletins, actions: []Action{ActionRead, ActionGenerate}},
	{resource: ResourceUsers, actions: []Action{ActionRead, ActionWrite}},
	{resource: ResourceSettingsTTS, actions: []Action{ActionRead, ActionWrite}},
	{resource: ResourcePronunciationRules, actions: []Action{ActionRead, ActionWrite}},
}

// EffectivePermissions expands wildcard policies into concrete resource actions.
func (s *Service) EffectivePermissions(subject string) (PermissionSet, error) {
	permissions := PermissionSet{}
	for _, capability := range permissionCatalog {
		for _, action := range capability.actions {
			allowed, err := s.enforcer.Enforce(subject, string(capability.resource), string(action))
			if err != nil {
				return nil, fmt.Errorf("evaluate %s/%s permission: %w", capability.resource, action, err)
			}
			if allowed {
				resource := string(capability.resource)
				permissions[resource] = append(permissions[resource], string(action))
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
