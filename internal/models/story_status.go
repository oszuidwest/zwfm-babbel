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

// IsValid reports whether the status is a valid value.
func (s StoryStatus) IsValid() bool {
	switch s {
	case StoryStatusDraft, StoryStatusActive, StoryStatusExpired:
		return true
	}
	return false
}

// String returns the string representation of the status.
func (s StoryStatus) String() string {
	return string(s)
}
