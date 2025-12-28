// Package models defines the data models for the Babbel API.
package models

import (
	"time"

	"gorm.io/gorm"
)

// Station represents a radio station.
type Station struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Name is the station's display name.
	Name string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	// MaxStoriesPerBlock is the maximum stories per bulletin.
	MaxStoriesPerBlock int `gorm:"not null;default:5" json:"max_stories_per_block"`
	// PauseSeconds is the pause duration between stories.
	PauseSeconds float64 `gorm:"not null;default:0" json:"pause_seconds"`
	// CreatedAt is when the station was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	// UpdatedAt is when the station was last modified.
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	StationVoices []StationVoice `gorm:"foreignKey:StationID" json:"-"`
	Bulletins     []Bulletin     `gorm:"foreignKey:StationID" json:"-"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Title is the story's headline.
	Title string `gorm:"size:255;not null" json:"title"`
	// Text is the story content for text-to-speech.
	Text string `gorm:"type:text" json:"text"`
	// VoiceID is the voice used for text-to-speech generation.
	VoiceID *int64 `gorm:"index" json:"voice_id"`
	// AudioFile is the path to the generated audio file.
	AudioFile string `gorm:"size:500" json:"audio_file"`
	// DurationSeconds is the length of the audio in seconds.
	DurationSeconds *float64 `json:"duration_seconds"`
	// Status is the story lifecycle state: draft, active, or expired.
	Status StoryStatus `gorm:"size:20;not null;default:'draft';index" json:"status"`
	// StartDate is when the story becomes active.
	StartDate time.Time `gorm:"not null;index" json:"start_date"`
	// EndDate is when the story expires.
	EndDate time.Time `gorm:"not null;index" json:"end_date"`
	// Monday indicates if the story is scheduled for Mondays.
	Monday bool `gorm:"not null;default:false" json:"monday"`
	// Tuesday indicates if the story is scheduled for Tuesdays.
	Tuesday bool `gorm:"not null;default:false" json:"tuesday"`
	// Wednesday indicates if the story is scheduled for Wednesdays.
	Wednesday bool `gorm:"not null;default:false" json:"wednesday"`
	// Thursday indicates if the story is scheduled for Thursdays.
	Thursday bool `gorm:"not null;default:false" json:"thursday"`
	// Friday indicates if the story is scheduled for Fridays.
	Friday bool `gorm:"not null;default:false" json:"friday"`
	// Saturday indicates if the story is scheduled for Saturdays.
	Saturday bool `gorm:"not null;default:false" json:"saturday"`
	// Sunday indicates if the story is scheduled for Sundays.
	Sunday bool `gorm:"not null;default:false" json:"sunday"`
	// Metadata stores additional custom data as JSON.
	Metadata *string `gorm:"type:json" json:"metadata"`
	// CreatedAt is when the story was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	// UpdatedAt is when the story was last modified.
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	// DeletedAt is when the story was soft-deleted, if applicable.
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`

	// Relations
	Voice *Voice `gorm:"foreignKey:VoiceID" json:"-"`

	// Fields populated by joins (not GORM relations)
	VoiceName     string  `gorm:"-" json:"voice_name"`
	VoiceJingle   string  `gorm:"-" json:"-"`
	VoiceMixPoint float64 `gorm:"-" json:"-"`
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

// WeekdaysMap returns the story's weekday schedule as a map.
//
// The returned map uses lowercase weekday names as keys ("monday" through "sunday")
// with boolean values indicating whether the story is scheduled for each day.
// This format provides a consistent interface for API responses.
func (s *Story) WeekdaysMap() map[string]bool {
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
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Name is the voice's display name.
	Name string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	// CreatedAt is when the voice was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	// UpdatedAt is when the voice was last modified.
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	Stories       []Story        `gorm:"foreignKey:VoiceID" json:"-"`
	StationVoices []StationVoice `gorm:"foreignKey:VoiceID" json:"-"`
}

// StationVoice represents the many-to-many relationship between stations and voices.
type StationVoice struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// StationID is the associated station's identifier.
	StationID int64 `gorm:"not null;uniqueIndex:idx_station_voice" json:"station_id"`
	// VoiceID is the associated voice's identifier.
	VoiceID int64 `gorm:"not null;uniqueIndex:idx_station_voice" json:"voice_id"`
	// AudioFile is the path to the station-specific jingle audio file.
	AudioFile string `gorm:"size:500" json:"-"`
	// MixPoint is the time offset (in seconds) where story audio is mixed into the jingle.
	MixPoint float64 `gorm:"not null;default:0" json:"mix_point"`
	// CreatedAt is when the station voice was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	// UpdatedAt is when the station voice was last modified.
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	// Relations
	Station *Station `gorm:"foreignKey:StationID" json:"-"`
	Voice   *Voice   `gorm:"foreignKey:VoiceID" json:"-"`

	// Fields populated by joins (not GORM relations)
	// StationName is the name of the associated station.
	StationName string `gorm:"-" json:"station_name,omitempty"`
	// VoiceName is the name of the associated voice.
	VoiceName string `gorm:"-" json:"voice_name,omitempty"`

	// AudioURL is dynamically generated for API responses.
	AudioURL *string `gorm:"-" json:"audio_url,omitempty"`
}

// User represents a system user with authentication credentials and role-based permissions.
type User struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Username is the unique login name.
	Username string `gorm:"size:255;not null;uniqueIndex" json:"username"`
	// FullName is the user's display name.
	FullName string `gorm:"size:255;not null" json:"full_name"`
	// PasswordHash is the bcrypt hashed password.
	PasswordHash string `gorm:"size:255" json:"-"`
	// Email is the optional email address.
	Email *string `gorm:"size:255;uniqueIndex" json:"email"`
	// Role defines the user's access level: admin, editor, or viewer
	Role UserRole `gorm:"size:20;not null;default:'viewer';index" json:"role"`
	// SuspendedAt is the timestamp when the account was suspended.
	SuspendedAt *time.Time `json:"suspended_at,omitempty"`
	// DeletedAt is the soft delete timestamp.
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
	// LastLoginAt is the timestamp of the most recent login.
	LastLoginAt *time.Time `json:"last_login_at"`
	// LoginCount is the total number of successful logins.
	LoginCount int `gorm:"not null;default:0" json:"login_count"`
	// FailedLoginAttempts is the consecutive failed login attempts for account locking.
	FailedLoginAttempts int `gorm:"not null;default:0" json:"-"`
	// LockedUntil is the timestamp until which the account is locked after failed attempts.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
	// PasswordChangedAt is the timestamp of the last password change.
	PasswordChangedAt *time.Time `json:"password_changed_at,omitempty"`
	// Metadata is optional JSON metadata.
	Metadata *string `gorm:"type:json" json:"metadata"`
	// CreatedAt is the timestamp when the user was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`
	// UpdatedAt is the timestamp of the last update.
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
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
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// StationID is the foreign key reference to the station this bulletin belongs to.
	StationID int64 `gorm:"not null;index" json:"station_id"`
	// Filename is the user-facing filename for the bulletin.
	Filename string `gorm:"size:255;not null" json:"filename"`
	// AudioFile is the internal file system path to the generated audio file.
	AudioFile string `gorm:"size:500" json:"-"`
	// DurationSeconds is the total duration of the bulletin in seconds.
	DurationSeconds float64 `gorm:"not null;default:0" json:"duration_seconds"`
	// FileSize is the size of the audio file in bytes.
	FileSize int64 `gorm:"not null;default:0" json:"file_size"`
	// StoryCount is the number of stories included in this bulletin.
	StoryCount int `gorm:"not null;default:0" json:"story_count"`
	// Metadata stores additional custom data as JSON.
	Metadata *string `gorm:"type:json" json:"metadata"`
	// CreatedAt is when the bulletin was generated.
	CreatedAt time.Time `gorm:"autoCreateTime;index" json:"created_at"`

	// Relations
	Station *Station        `gorm:"foreignKey:StationID" json:"-"`
	Stories []BulletinStory `gorm:"foreignKey:BulletinID" json:"-"`

	// Fields populated by joins (not GORM relations)
	// StationName is the name of the station this bulletin belongs to.
	StationName string `gorm:"-" json:"station_name,omitempty"`
}

// BulletinStory represents the relationship between bulletins and stories with join data.
type BulletinStory struct {
	// ID is the unique identifier for this bulletin-story relationship.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// BulletinID is the foreign key reference to the bulletin.
	BulletinID int64 `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"bulletin_id"`
	// StoryID is the foreign key reference to the story.
	StoryID int64 `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"story_id"`
	// StoryOrder is the position of this story within the bulletin sequence.
	StoryOrder int `gorm:"not null;default:0" json:"story_order"`
	// CreatedAt is when this relationship was created.
	CreatedAt time.Time `gorm:"autoCreateTime" json:"created_at"`

	// Relations
	Bulletin *Bulletin `gorm:"foreignKey:BulletinID" json:"-"`
	Story    *Story    `gorm:"foreignKey:StoryID" json:"-"`

	// Fields populated by joins (not GORM relations)
	// StationID is the station ID from the bulletin.
	StationID int64 `gorm:"-" json:"-"`
	// StationName is the station name from the bulletin.
	StationName string `gorm:"-" json:"-"`
	// StoryTitle is the title of the story.
	StoryTitle string `gorm:"-" json:"-"`
	// BulletinFilename is the filename of the bulletin.
	BulletinFilename string `gorm:"-" json:"-"`
}

// StoryBulletinHistory represents a bulletin with story-specific metadata for history queries.
type StoryBulletinHistory struct {
	Bulletin // Embed the full Bulletin struct
	// StoryOrder is the position of the story within this bulletin.
	StoryOrder int `gorm:"-" json:"story_order"`
	// IncludedAt is when the story was included in this bulletin.
	IncludedAt time.Time `gorm:"-" json:"included_at"`
}
