// Package auth provides authentication and authorization services.
package auth

// Resource represents a protected resource type
type Resource string

// Resources that can be protected by RBAC.
const (
	// ResourceStations represents radio station resources
	ResourceStations Resource = "stations"
	// ResourceVoices represents text-to-speech voice resources
	ResourceVoices Resource = "voices"
	// ResourceStories represents news story resources
	ResourceStories Resource = "stories"
	// ResourceBulletins represents generated audio bulletin resources
	ResourceBulletins Resource = "bulletins"
	// ResourceUsers represents user account resources
	ResourceUsers Resource = "users"
	// ResourceStationVoices represents station-voice junction resources
	ResourceStationVoices Resource = "station_voices"
)

// Action represents an operation on a resource
type Action string

// Actions that can be performed on resources.
const (
	// ActionRead represents read/list operations
	ActionRead Action = "read"
	// ActionWrite represents create/update/delete operations
	ActionWrite Action = "write"
	// ActionGenerate represents bulletin generation operations
	ActionGenerate Action = "generate"
)
