package auth

// Resource represents a protected resource type
type Resource string

const (
	ResourceStations      Resource = "stations"
	ResourceVoices        Resource = "voices"
	ResourceStories       Resource = "stories"
	ResourceBulletins     Resource = "bulletins"
	ResourceUsers         Resource = "users"
	ResourceStationVoices Resource = "station_voices"
)

// Action represents an operation on a resource
type Action string

const (
	ActionRead     Action = "read"
	ActionWrite    Action = "write"
	ActionGenerate Action = "generate"
)
