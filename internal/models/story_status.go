package models

// StoryStatus represents the lifecycle state of a story.
type StoryStatus string

// Story status values for workflow management.
const (
	// StoryStatusDraft indicates a story is being edited.
	StoryStatusDraft StoryStatus = "draft"
	// StoryStatusActive indicates a story is published and available.
	StoryStatusActive StoryStatus = "active"
	// StoryStatusExpired indicates a story has passed its end date.
	StoryStatusExpired StoryStatus = "expired"
)
