// Package models defines the data models for the Babbel API.
package models

import (
	"time"
)

// Station represents a radio station.
type Station struct {
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// Name is the station's display name.
	Name string `db:"name" json:"name"`
	// MaxStoriesPerBlock is the maximum stories per bulletin.
	MaxStoriesPerBlock int `db:"max_stories_per_block" json:"max_stories_per_block"`
	// PauseSeconds is the pause duration between stories.
	PauseSeconds float64 `db:"pause_seconds" json:"pause_seconds"`
	// CreatedAt is when the station was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	// UpdatedAt is when the station was last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// Title is the story's headline.
	Title string `db:"title" json:"title"`
	// Text is the story content for text-to-speech.
	Text string `db:"text" json:"text"`
	// VoiceID is the voice used for text-to-speech generation.
	VoiceID *int64 `db:"voice_id" json:"voice_id"`
	// AudioFile is the path to the generated audio file.
	AudioFile string `db:"audio_file" json:"audio_file"`
	// DurationSeconds is the length of the audio in seconds.
	DurationSeconds *float64 `db:"duration_seconds" json:"duration_seconds"`
	// Status is the story lifecycle state: draft, active, or expired.
	Status StoryStatus `db:"status" json:"status"`
	// StartDate is when the story becomes active.
	StartDate time.Time `db:"start_date" json:"start_date"`
	// EndDate is when the story expires.
	EndDate time.Time `db:"end_date" json:"end_date"`
	// Monday indicates if the story is scheduled for Mondays.
	Monday bool `db:"monday" json:"monday"`
	// Tuesday indicates if the story is scheduled for Tuesdays.
	Tuesday bool `db:"tuesday" json:"tuesday"`
	// Wednesday indicates if the story is scheduled for Wednesdays.
	Wednesday bool `db:"wednesday" json:"wednesday"`
	// Thursday indicates if the story is scheduled for Thursdays.
	Thursday bool `db:"thursday" json:"thursday"`
	// Friday indicates if the story is scheduled for Fridays.
	Friday bool `db:"friday" json:"friday"`
	// Saturday indicates if the story is scheduled for Saturdays.
	Saturday bool `db:"saturday" json:"saturday"`
	// Sunday indicates if the story is scheduled for Sundays.
	Sunday bool `db:"sunday" json:"sunday"`
	// Metadata stores additional custom data as JSON.
	Metadata *string `db:"metadata" json:"metadata"`
	// CreatedAt is when the story was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	// UpdatedAt is when the story was last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
	// DeletedAt is when the story was soft-deleted, if applicable.
	DeletedAt *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`

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
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// Name is the voice's display name.
	Name string `db:"name" json:"name"`
	// CreatedAt is when the voice was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	// UpdatedAt is when the voice was last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// StationVoice represents the many-to-many relationship between stations and voices.
type StationVoice struct {
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// StationID is the associated station's identifier.
	StationID int64 `db:"station_id" json:"station_id"`
	// VoiceID is the associated voice's identifier.
	VoiceID int64 `db:"voice_id" json:"voice_id"`
	// AudioFile is the path to the station-specific jingle audio file.
	AudioFile string `db:"audio_file" json:"-"`
	// MixPoint is the time offset (in seconds) where story audio is mixed into the jingle.
	MixPoint float64 `db:"mix_point" json:"mix_point"`
	// CreatedAt is when the station voice was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	// UpdatedAt is when the station voice was last modified.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`

	// Relations populated by joins
	// StationName is the name of the associated station.
	StationName string `db:"station_name" json:"station_name,omitempty"`
	// VoiceName is the name of the associated voice.
	VoiceName string `db:"voice_name" json:"voice_name,omitempty"`

	// AudioURL is dynamically generated for API responses.
	AudioURL *string `json:"audio_url,omitempty"`
}

// Broadcast represents a historical record of when a story was broadcast.
type Broadcast struct {
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// StationID is the broadcasting station.
	StationID int64 `db:"station_id" json:"station_id"`
	// StoryID is the story that was broadcast.
	StoryID int64 `db:"story_id" json:"story_id"`
	// CreatedAt is when the broadcast occurred.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// User represents a system user with authentication credentials and role-based permissions.
type User struct {
	// ID is the unique identifier.
	ID int64 `db:"id" json:"id"`
	// Username is the unique login name.
	Username string `db:"username" json:"username"`
	// FullName is the user's display name.
	FullName string `db:"full_name" json:"full_name"`
	// PasswordHash is the bcrypt hashed password.
	PasswordHash string `db:"password_hash" json:"-"`
	// Email is the optional email address.
	Email *string `db:"email" json:"email"`
	// Role defines the user's access level: admin, editor, or viewer
	Role UserRole `db:"role" json:"role"`
	// SuspendedAt is the timestamp when the account was suspended.
	SuspendedAt *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	// DeletedAt is the soft delete timestamp.
	DeletedAt *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
	// LastLoginAt is the timestamp of the most recent login.
	LastLoginAt *time.Time `db:"last_login_at" json:"last_login_at"`
	// LoginCount is the total number of successful logins.
	LoginCount int `db:"login_count" json:"login_count"`
	// FailedLoginAttempts is the consecutive failed login attempts for account locking.
	FailedLoginAttempts int `db:"failed_login_attempts" json:"-"`
	// LockedUntil is the timestamp until which the account is locked after failed attempts.
	LockedUntil *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	// PasswordChangedAt is the timestamp of the last password change.
	PasswordChangedAt *time.Time `db:"password_changed_at" json:"password_changed_at,omitempty"`
	// Metadata is optional JSON metadata.
	Metadata *string `db:"metadata" json:"metadata"`
	// CreatedAt is the timestamp when the user was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	// UpdatedAt is the timestamp of the last update.
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// UserSession represents an active authentication session.
type UserSession struct {
	ID        int64     `db:"id" json:"id"`
	UserID    int64     `db:"user_id" json:"user_id"`
	TokenHash string    `db:"token_hash" json:"-"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	UserAgent string    `db:"user_agent" json:"user_agent"`
	IPAddress string    `db:"ip_address" json:"ip_address"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// UserRole represents a user's permission level.
type UserRole string

// Role permission levels for the RBAC system.
const (
	// RoleAdmin grants full administrative access.
	RoleAdmin UserRole = "admin"
	// RoleEditor allows content management without user administration.
	RoleEditor UserRole = "editor"
	// RoleViewer provides read-only access to content.
	RoleViewer UserRole = "viewer"
)

// IsValid checks if the role is valid.
func (r UserRole) IsValid() bool {
	switch r {
	case RoleAdmin, RoleEditor, RoleViewer:
		return true
	}
	return false
}

// String returns the string representation of the role.
func (r UserRole) String() string {
	return string(r)
}

// Bulletin represents a completed audio bulletin generated from multiple stories.
type Bulletin struct {
	// ID is the unique identifier for this bulletin.
	ID int64 `db:"id" json:"id"`
	// StationID is the foreign key reference to the station this bulletin belongs to.
	StationID int64 `db:"station_id" json:"station_id"`
	// Filename is the user-facing filename for the bulletin.
	Filename string `db:"filename" json:"filename"`
	// AudioFile is the internal file system path to the generated audio file.
	AudioFile string `db:"audio_file" json:"-"`
	// DurationSeconds is the total duration of the bulletin in seconds.
	DurationSeconds float64 `db:"duration_seconds" json:"duration_seconds"`
	// FileSize is the size of the audio file in bytes.
	FileSize int64 `db:"file_size" json:"file_size"`
	// StoryCount is the number of stories included in this bulletin.
	StoryCount int `db:"story_count" json:"story_count"`
	// Metadata stores additional custom data as JSON.
	Metadata *string `db:"metadata" json:"metadata"`
	// CreatedAt is when the bulletin was generated.
	CreatedAt time.Time `db:"created_at" json:"created_at"`

	// Relations populated by joins
	// StationName is the name of the station this bulletin belongs to.
	StationName string `db:"station_name" json:"station_name,omitempty"`
}

// BulletinStory represents the relationship between bulletins and stories with join data.
type BulletinStory struct {
	// ID is the unique identifier for this bulletin-story relationship.
	ID int64 `db:"id" json:"id"`
	// BulletinID is the foreign key reference to the bulletin.
	BulletinID int64 `db:"bulletin_id" json:"bulletin_id"`
	// StoryID is the foreign key reference to the story.
	StoryID int64 `db:"story_id" json:"story_id"`
	// StoryOrder is the position of this story within the bulletin sequence.
	StoryOrder int `db:"story_order" json:"story_order"`
	// CreatedAt is when this relationship was created.
	CreatedAt time.Time `db:"created_at" json:"created_at"`

	// Joined fields from related tables
	// StationID is the station ID from the bulletin.
	StationID int64 `db:"station_id" json:"-"`
	// StationName is the station name from the bulletin.
	StationName string `db:"station_name" json:"-"`
	// StoryTitle is the title of the story.
	StoryTitle string `db:"story_title" json:"-"`
	// BulletinFilename is the filename of the bulletin.
	BulletinFilename string `db:"bulletin_filename" json:"-"`
}

// StoryBulletinHistory represents a bulletin with story-specific metadata for history queries.
type StoryBulletinHistory struct {
	Bulletin // Embed the full Bulletin struct
	// StoryOrder is the position of the story within this bulletin.
	StoryOrder int `db:"story_order" json:"story_order"`
	// IncludedAt is when the story was included in this bulletin.
	IncludedAt time.Time `db:"included_at" json:"included_at"`
}
