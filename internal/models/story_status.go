package models

// StoryStatus represents the lifecycle state of a story
type StoryStatus string

const (
	StoryStatusDraft   StoryStatus = "draft"
	StoryStatusActive  StoryStatus = "active"
	StoryStatusExpired StoryStatus = "expired"
)

// IsValid checks if the status is a valid value
func (s StoryStatus) IsValid() bool {
	switch s {
	case StoryStatusDraft, StoryStatusActive, StoryStatusExpired:
		return true
	}
	return false
}

// String returns the string representation
func (s StoryStatus) String() string {
	return string(s)
}
