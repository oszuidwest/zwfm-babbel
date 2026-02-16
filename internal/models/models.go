// Package models defines the data models for the Babbel API.
package models

import (
	"fmt"
	"time"

	"gorm.io/datatypes"
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
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the station was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// Relations
	StationVoices []StationVoice `gorm:"foreignKey:StationID" json:"-"`
	Bulletins     []Bulletin     `gorm:"foreignKey:StationID" json:"-"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Title is the story's headline.
	Title string `gorm:"size:500;not null" json:"title"`
	// Text is the story content for text-to-speech.
	Text string `gorm:"type:text" json:"text"`
	// VoiceID is the voice used for text-to-speech generation.
	VoiceID *int64 `gorm:"index" json:"voice_id"`
	// AudioFile is the filename of the generated audio file (empty if no audio).
	AudioFile string `gorm:"size:500" json:"audio_file"`
	// DurationSeconds is the length of the audio in seconds.
	DurationSeconds *float64 `json:"duration_seconds"`
	// Status is the story lifecycle state: draft, active, or expired.
	Status StoryStatus `gorm:"size:20;not null;default:'draft';index" json:"status"`
	// StartDate is when the story becomes active.
	StartDate time.Time `gorm:"not null;index" json:"start_date"`
	// EndDate is when the story expires.
	EndDate time.Time `gorm:"not null;index" json:"end_date"`
	// Weekdays is a bitmask for scheduling on specific days (0-127, where 127 = all days).
	Weekdays Weekdays `gorm:"not null;default:127;index" json:"weekdays"`
	// Metadata stores additional custom data as JSON.
	Metadata *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	// CreatedAt is when the story was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the story was last modified.
	UpdatedAt time.Time `json:"updated_at"`
	// DeletedAt is when the story was soft-deleted, if applicable.
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`

	// Relations
	Voice *Voice `gorm:"foreignKey:VoiceID" json:"-"`

	// Computed fields (populated by AfterFind hook, not stored in DB)
	VoiceName string `gorm:"-" json:"voice_name,omitempty"`
	AudioURL  string `gorm:"-" json:"audio_url"`
}

// AfterFind populates computed fields from preloaded relations.
func (s *Story) AfterFind(_ *gorm.DB) error {
	// Populate voice name from preloaded relation
	if s.Voice != nil {
		s.VoiceName = s.Voice.Name
	}

	// Always generate audio URL (endpoint exists, may return 404 if no file)
	s.AudioURL = fmt.Sprintf("/stories/%d/audio", s.ID)

	return nil
}

// IsActiveOnWeekday reports whether the story is scheduled for the given weekday.
func (s *Story) IsActiveOnWeekday(weekday time.Weekday) bool {
	return s.Weekdays.IsActive(weekday)
}

// Voice represents a text-to-speech voice configuration.
type Voice struct {
	// ID is the unique identifier.
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Name is the voice's display name.
	Name string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	// CreatedAt is when the voice was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the voice was last modified.
	UpdatedAt time.Time `json:"updated_at"`

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
	// AudioFile is the filename of the station-specific jingle audio file (empty if no audio).
	AudioFile string `gorm:"size:500" json:"audio_file"`
	// MixPoint is the time offset (in seconds) where story audio is mixed into the jingle.
	MixPoint float64 `gorm:"not null;default:0" json:"mix_point"`
	// CreatedAt is when the station voice was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the station voice was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// Relations
	Station *Station `gorm:"foreignKey:StationID" json:"-"`
	Voice   *Voice   `gorm:"foreignKey:VoiceID" json:"-"`

	// Computed fields (populated by AfterFind hook, not stored in DB)
	StationName string `gorm:"-" json:"station_name,omitempty"`
	VoiceName   string `gorm:"-" json:"voice_name,omitempty"`
	AudioURL    string `gorm:"-" json:"audio_url"`
}

// AfterFind populates computed fields from preloaded relations.
func (sv *StationVoice) AfterFind(_ *gorm.DB) error {
	// Populate station name from preloaded relation
	if sv.Station != nil {
		sv.StationName = sv.Station.Name
	}

	// Populate voice name from preloaded relation
	if sv.Voice != nil {
		sv.VoiceName = sv.Voice.Name
	}

	// Always generate audio URL (endpoint exists, may return 404 if no file)
	sv.AudioURL = fmt.Sprintf("/station-voices/%d/audio", sv.ID)

	return nil
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
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
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
	Metadata *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	// CreatedAt is the timestamp when the user was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is the timestamp of the last update.
	UpdatedAt time.Time `json:"updated_at"`
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

// IsValid reports whether the role is valid.
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
	Metadata *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	// CreatedAt is when the bulletin was generated.
	CreatedAt time.Time `gorm:"index" json:"created_at"`

	// Relations
	Station *Station        `gorm:"foreignKey:StationID" json:"-"`
	Stories []BulletinStory `gorm:"foreignKey:BulletinID" json:"-"`

	// Computed fields (populated by AfterFind hook, not stored in DB)
	StationName string `gorm:"-" json:"station_name,omitempty"`
	AudioURL    string `gorm:"-" json:"audio_url,omitempty"`
}

// AfterFind populates computed fields from preloaded relations.
func (b *Bulletin) AfterFind(_ *gorm.DB) error {
	// Populate station name from preloaded relation
	if b.Station != nil {
		b.StationName = b.Station.Name
	}

	// Generate audio URL
	b.AudioURL = fmt.Sprintf("/bulletins/%d/audio", b.ID)

	return nil
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
	CreatedAt time.Time `json:"created_at"`

	// Relations
	Bulletin *Bulletin `gorm:"foreignKey:BulletinID" json:"-"`
	Story    *Story    `gorm:"foreignKey:StoryID" json:"-"`
}
