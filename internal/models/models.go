// Package models defines the data models for the Babbel API.
package models

import (
	"time"
)

// Station represents a radio station.
type Station struct {
	ID                 int       `db:"id" json:"id"`
	Name               string    `db:"name" json:"name"`
	MaxStoriesPerBlock int       `db:"max_stories_per_block" json:"max_stories_per_block"`
	PauseSeconds       float64   `db:"pause_seconds" json:"pause_seconds"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time `db:"updated_at" json:"updated_at"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	ID              int         `db:"id" json:"id"`
	Title           string      `db:"title" json:"title"`
	Text            string      `db:"text" json:"text"`
	VoiceID         *int        `db:"voice_id" json:"voice_id"`
	AudioFile       string      `db:"audio_file" json:"audio_file"`
	DurationSeconds *float64    `db:"duration_seconds" json:"duration_seconds"`
	Status          StoryStatus `db:"status" json:"status"` // draft, active, expired
	StartDate       time.Time   `db:"start_date" json:"start_date"`
	EndDate         time.Time   `db:"end_date" json:"end_date"`
	Monday          bool        `db:"monday" json:"monday"`
	Tuesday         bool        `db:"tuesday" json:"tuesday"`
	Wednesday       bool        `db:"wednesday" json:"wednesday"`
	Thursday        bool        `db:"thursday" json:"thursday"`
	Friday          bool        `db:"friday" json:"friday"`
	Saturday        bool        `db:"saturday" json:"saturday"`
	Sunday          bool        `db:"sunday" json:"sunday"`
	Metadata        *string     `db:"metadata" json:"metadata"`
	CreatedAt       time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time   `db:"updated_at" json:"updated_at"`
	DeletedAt       *time.Time  `db:"deleted_at" json:"deleted_at,omitempty"`

	// Relations populated by joins
	VoiceName     string  `db:"voice_name" json:"voice_name"`
	VoiceJingle   string  `db:"voice_jingle" json:"-"`
	VoiceMixPoint float64 `db:"voice_mix_point" json:"-"`
}

// IsActiveOnWeekday returns whether the story is scheduled for the given weekday.
func (s *Story) IsActiveOnWeekday(weekday time.Weekday) bool {
	switch weekday {
	case time.Monday:
		return s.Monday
	case time.Tuesday:
		return s.Tuesday
	case time.Wednesday:
		return s.Wednesday
	case time.Thursday:
		return s.Thursday
	case time.Friday:
		return s.Friday
	case time.Saturday:
		return s.Saturday
	case time.Sunday:
		return s.Sunday
	default:
		return false
	}
}

// GetWeekdaysMap returns the story's weekday schedule as a map.
//
// The returned map uses lowercase weekday names as keys ("monday" through "sunday")
// with boolean values indicating whether the story is scheduled for each day.
// This format provides a consistent interface for API responses.
func (s *Story) GetWeekdaysMap() map[string]bool {
	return map[string]bool{
		"monday":    s.Monday,
		"tuesday":   s.Tuesday,
		"wednesday": s.Wednesday,
		"thursday":  s.Thursday,
		"friday":    s.Friday,
		"saturday":  s.Saturday,
		"sunday":    s.Sunday,
	}
}

// Voice represents a text-to-speech voice configuration.
type Voice struct {
	ID        int       `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// StationVoice represents the many-to-many relationship between stations and voices.
type StationVoice struct {
	ID        int    `db:"id" json:"id"`
	StationID int    `db:"station_id" json:"station_id"`
	VoiceID   int    `db:"voice_id" json:"voice_id"`
	AudioFile string `db:"audio_file" json:"-"`
	// MixPoint is the time offset (in seconds) where story audio is mixed into the jingle
	MixPoint  float64   `db:"mix_point" json:"mix_point"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`

	// Relations populated by joins
	StationName string `db:"station_name" json:"station_name,omitempty"`
	VoiceName   string `db:"voice_name" json:"voice_name,omitempty"`

	// AudioURL is dynamically generated for API responses
	AudioURL *string `json:"audio_url,omitempty"`
}

// Broadcast represents a historical record of when a story was broadcast.
type Broadcast struct {
	ID        int       `db:"id" json:"id"`
	StationID int       `db:"station_id" json:"station_id"`
	StoryID   int       `db:"story_id" json:"story_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// User represents a system user with authentication credentials and role-based permissions.
type User struct {
	ID           int     `db:"id" json:"id"`
	Username     string  `db:"username" json:"username"`
	FullName     string  `db:"full_name" json:"full_name"`
	PasswordHash string  `db:"password_hash" json:"-"`
	Email        *string `db:"email" json:"email"`
	// Role defines the user's access level: admin, editor, or viewer
	Role                UserRole   `db:"role" json:"role"`
	SuspendedAt         *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	DeletedAt           *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
	LastLoginAt         *time.Time `db:"last_login_at" json:"last_login_at"`
	LoginCount          int        `db:"login_count" json:"login_count"`
	FailedLoginAttempts int        `db:"failed_login_attempts" json:"-"`
	LockedUntil         *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	PasswordChangedAt   *time.Time `db:"password_changed_at" json:"password_changed_at,omitempty"`
	Metadata            *string    `db:"metadata" json:"metadata"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`
}

// UserSession represents an active authentication session.
type UserSession struct {
	ID        int       `db:"id" json:"id"`
	UserID    int       `db:"user_id" json:"user_id"`
	TokenHash string    `db:"token_hash" json:"-"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	UserAgent string    `db:"user_agent" json:"user_agent"`
	IPAddress string    `db:"ip_address" json:"ip_address"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// UserRole represents a user's permission level
type UserRole string

// Role permission levels for the RBAC system.
const (
	RoleAdmin  UserRole = "admin"
	RoleEditor UserRole = "editor"
	RoleViewer UserRole = "viewer"
)

// IsValid checks if the role is valid
func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleEditor, RoleViewer:
		return true
	}
	return false
}

// String returns the string representation
func (r UserRole) String() string {
	return string(r)
}

// Bulletin represents a completed audio bulletin generated from multiple stories.
type Bulletin struct {
	ID              int       `db:"id" json:"id"`
	StationID       int       `db:"station_id" json:"station_id"`
	Filename        string    `db:"filename" json:"filename"`
	AudioFile       string    `db:"audio_file" json:"-"`
	DurationSeconds float64   `db:"duration_seconds" json:"duration_seconds"`
	FileSize        int64     `db:"file_size" json:"file_size"`
	StoryCount      int       `db:"story_count" json:"story_count"`
	Metadata        *string   `db:"metadata" json:"metadata"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`

	// Relations populated by joins
	StationName string `db:"station_name" json:"station_name,omitempty"`
}

// BulletinStory represents the relationship between bulletins and stories with join data.
type BulletinStory struct {
	ID         int       `db:"id" json:"id"`
	BulletinID int       `db:"bulletin_id" json:"bulletin_id"`
	StoryID    int       `db:"story_id" json:"story_id"`
	StoryOrder int       `db:"story_order" json:"story_order"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`

	// Joined fields from related tables
	StationID        int    `db:"station_id" json:"-"`
	StationName      string `db:"station_name" json:"-"`
	StoryTitle       string `db:"story_title" json:"-"`
	BulletinFilename string `db:"bulletin_filename" json:"-"`
}

// StoryBulletinHistory represents a bulletin with story-specific metadata for history queries.
type StoryBulletinHistory struct {
	Bulletin             // Embed the full Bulletin struct
	StoryOrder int       `db:"story_order" json:"story_order"`
	IncludedAt time.Time `db:"included_at" json:"included_at"`
}
