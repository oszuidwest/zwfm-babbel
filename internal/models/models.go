// Package models contains the data models for the Babbel API.
package models

import (
	"time"
)

// Station represents a radio station
type Station struct {
	ID                 int       `db:"id" json:"id"`
	Name               string    `db:"name" json:"name"`
	MaxStoriesPerBlock int       `db:"max_stories_per_block" json:"max_stories_per_block"`
	PauseSeconds       float64   `db:"pause_seconds" json:"pause_seconds"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
	UpdatedAt          time.Time `db:"updated_at" json:"updated_at"`
}

// Story represents a news story
type Story struct {
	ID              int        `db:"id" json:"id"`
	Title           string     `db:"title" json:"title"`
	Text            string     `db:"text" json:"text"` // Plaintext content
	VoiceID         *int       `db:"voice_id" json:"voice_id"`
	AudioFile       string     `db:"audio_file" json:"audio_file"`
	DurationSeconds *float64   `db:"duration_seconds" json:"duration_seconds"`
	Status          string     `db:"status" json:"status"` // draft, active, expired
	StartDate       time.Time  `db:"start_date" json:"start_date"`
	EndDate         time.Time  `db:"end_date" json:"end_date"`
	Weekdays        uint8      `db:"weekdays" json:"weekdays"` // bitmask: 1=Mon, 2=Tue, 4=Wed, 8=Thu, 16=Fri, 32=Sat, 64=Sun
	Metadata        *string    `db:"metadata" json:"metadata"` // JSON metadata
	CreatedAt       time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt       *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`

	// Relations (filled by joins)
	VoiceName string `db:"voice_name" json:"voice_name"`
	// These fields are populated from station_voices table via JOIN during bulletin generation
	VoiceJingle   string  `db:"voice_jingle" json:"-"`    // Station-specific jingle path
	VoiceMixPoint float64 `db:"voice_mix_point" json:"-"` // Mix point in seconds
}

// Voice represents a news reader
type Voice struct {
	ID        int       `db:"id" json:"id"`
	Name      string    `db:"name" json:"name"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

// StationVoice represents the relationship between a station and voice with station-specific jingle
type StationVoice struct {
	ID         int       `db:"id" json:"id"`
	StationID  int       `db:"station_id" json:"station_id"`
	VoiceID    int       `db:"voice_id" json:"voice_id"`
	JingleFile string    `db:"jingle_file" json:"-"` // Hide from JSON
	MixPoint   float64   `db:"mix_point" json:"mix_point"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	UpdatedAt  time.Time `db:"updated_at" json:"updated_at"`

	// Relations (filled by joins)
	StationName string `db:"station_name" json:"station_name,omitempty"`
	VoiceName   string `db:"voice_name" json:"voice_name,omitempty"`

	// Computed fields
	AudioURL *string `json:"audio_url,omitempty"`
}

// Broadcast represents a broadcast history entry
type Broadcast struct {
	ID        int       `db:"id" json:"id"`
	StationID int       `db:"station_id" json:"station_id"`
	StoryID   int       `db:"story_id" json:"story_id"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// User represents a system user for authentication and access control
type User struct {
	ID                  int        `db:"id" json:"id"`
	Username            string     `db:"username" json:"username"`
	FullName            string     `db:"full_name" json:"full_name"`
	PasswordHash        string     `db:"password_hash" json:"-"`
	Email               *string    `db:"email" json:"email"`
	Role                string     `db:"role" json:"role"` // admin, editor, viewer
	SuspendedAt         *time.Time `db:"suspended_at" json:"suspended_at,omitempty"`
	LastLoginAt         *time.Time `db:"last_login_at" json:"last_login_at"`
	LoginCount          int        `db:"login_count" json:"login_count"`
	FailedLoginAttempts int        `db:"failed_login_attempts" json:"-"`
	LockedUntil         *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	PasswordChangedAt   time.Time  `db:"password_changed_at" json:"password_changed_at"`
	Metadata            *string    `db:"metadata" json:"metadata"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`
}

// UserSession represents an active user session
type UserSession struct {
	ID        int       `db:"id" json:"id"`
	UserID    int       `db:"user_id" json:"user_id"`
	TokenHash string    `db:"token_hash" json:"-"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	UserAgent string    `db:"user_agent" json:"user_agent"`
	IPAddress string    `db:"ip_address" json:"ip_address"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// Role constants define the access levels within the system.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// Weekday constants use bitmask pattern for efficient storage and querying.
const (
	Monday    = 1 << 0 // 1
	Tuesday   = 1 << 1 // 2
	Wednesday = 1 << 2 // 4
	Thursday  = 1 << 3 // 8
	Friday    = 1 << 4 // 16
	Saturday  = 1 << 5 // 32
	Sunday    = 1 << 6 // 64
)

// HasWeekday checks if a weekday is set in the bitmask
func (s *Story) HasWeekday(day uint8) bool {
	return s.Weekdays&day != 0
}

// Bulletin represents a generated news bulletin
type Bulletin struct {
	ID              int       `db:"id" json:"id"`
	StationID       int       `db:"station_id" json:"station_id"`
	Filename        string    `db:"filename" json:"filename"`
	FilePath        string    `db:"file_path" json:"file_path"`
	DurationSeconds float64   `db:"duration_seconds" json:"duration_seconds"`
	FileSize        int64     `db:"file_size" json:"file_size"`
	StoryCount      int       `db:"story_count" json:"story_count"`
	Metadata        *string   `db:"metadata" json:"metadata"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`

	// Relations (filled by joins)
	StationName string `db:"station_name" json:"station_name,omitempty"`
}
