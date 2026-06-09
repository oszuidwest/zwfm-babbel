// Package models defines the data models for the Babbel API.
package models

import (
	"fmt"
	"html"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Station represents a radio station.
type Station struct {
	ID   int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Name string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	// MaxStoriesPerBlock is the maximum stories per bulletin.
	MaxStoriesPerBlock int `gorm:"not null;default:5" json:"max_stories_per_block"`
	// PauseSeconds is the pause duration between stories.
	PauseSeconds float64   `gorm:"not null;default:0" json:"pause_seconds"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	// Relations are loaded by GORM when preloaded.
	StationVoices []StationVoice `gorm:"foreignKey:StationID" json:"-"`
	Bulletins     []Bulletin     `gorm:"foreignKey:StationID" json:"-"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	ID int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	// Title is the story's headline.
	Title string `gorm:"size:500;not null" json:"title"`
	// Text is the story content for text-to-speech.
	Text string `gorm:"type:text" json:"text"`
	// VoiceID is the voice used for text-to-speech generation.
	VoiceID *int64 `gorm:"index" json:"voice_id"`
	// AudioFile is the filename of the generated audio file (empty if no audio).
	AudioFile       string   `gorm:"size:500" json:"audio_file"`
	DurationSeconds *float64 `json:"duration_seconds"`
	// Status is the story lifecycle state: draft, active, or expired.
	Status StoryStatus `gorm:"size:20;not null;default:'draft';index" json:"status"`
	// StartDate is when the story becomes active.
	StartDate time.Time `gorm:"not null;index" json:"start_date"`
	// EndDate is when the story expires.
	EndDate time.Time `gorm:"not null;index" json:"end_date"`
	// Weekdays is a bitmask for scheduling on specific days (0-127, where 127 = all days).
	Weekdays Weekdays `gorm:"not null;default:127;index" json:"weekdays"`
	// IsBreaking marks a breaking news story prioritized above fair rotation in
	// bulletin selection.
	IsBreaking bool               `gorm:"not null;default:false;index" json:"is_breaking"`
	Metadata   *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
	DeletedAt  gorm.DeletedAt     `gorm:"index" json:"deleted_at"`

	// Relations are loaded by GORM when preloaded.
	Voice *Voice `gorm:"foreignKey:VoiceID" json:"-"`

	// Computed fields are populated by AfterFind and not stored in the database.
	VoiceName string `gorm:"-" json:"voice_name,omitempty"`
	AudioURL  string `gorm:"-" json:"audio_url"`
}

// AfterFind populates computed fields from preloaded relations and normalizes text.
func (s *Story) AfterFind(_ *gorm.DB) error {
	// Keep this compatibility path until a data migration normalizes HTML
	// entities in existing rows. It decodes older data stored before input-side
	// normalization was added (see NormalizeText in utils/http.go).
	s.Title = html.UnescapeString(s.Title)
	s.Text = html.UnescapeString(s.Text)

	if s.Voice != nil {
		s.VoiceName = s.Voice.Name
	}

	// Always generate an audio URL; the endpoint may return 404 if no file exists.
	s.AudioURL = fmt.Sprintf("/stories/%d/audio", s.ID)

	return nil
}

// IsActiveOnWeekday reports whether the story is scheduled for the given weekday.
func (s *Story) IsActiveOnWeekday(weekday time.Weekday) bool {
	return s.Weekdays.IsActive(weekday)
}

// Voice represents a text-to-speech voice configuration.
type Voice struct {
	ID   int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Name string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	// ElevenLabsVoiceID is the ElevenLabs voice identifier for TTS generation.
	ElevenLabsVoiceID *string   `gorm:"column:elevenlabs_voice_id;size:255" json:"elevenlabs_voice_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	// Relations are loaded by GORM when preloaded.
	Stories       []Story        `gorm:"foreignKey:VoiceID" json:"-"`
	StationVoices []StationVoice `gorm:"foreignKey:VoiceID" json:"-"`
}

// StationVoice represents the many-to-many relationship between stations and voices.
type StationVoice struct {
	ID        int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	StationID int64 `gorm:"not null;uniqueIndex:idx_station_voice" json:"station_id"`
	VoiceID   int64 `gorm:"not null;uniqueIndex:idx_station_voice" json:"voice_id"`
	// AudioFile is the filename of the station-specific jingle audio file (empty if no audio).
	AudioFile string `gorm:"size:500" json:"audio_file"`
	// MixPoint is the time offset (in seconds) where story audio is mixed into the jingle.
	MixPoint  float64   `gorm:"not null;default:0" json:"mix_point"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relations are loaded by GORM when preloaded.
	Station *Station `gorm:"foreignKey:StationID" json:"-"`
	Voice   *Voice   `gorm:"foreignKey:VoiceID" json:"-"`

	// Computed fields are populated by AfterFind and not stored in the database.
	StationName string `gorm:"-" json:"station_name,omitempty"`
	VoiceName   string `gorm:"-" json:"voice_name,omitempty"`
	AudioURL    string `gorm:"-" json:"audio_url"`
}

// AfterFind populates computed fields from preloaded relations.
func (sv *StationVoice) AfterFind(_ *gorm.DB) error {
	if sv.Station != nil {
		sv.StationName = sv.Station.Name
	}

	if sv.Voice != nil {
		sv.VoiceName = sv.Voice.Name
	}

	// Always generate an audio URL; the endpoint may return 404 if no file exists.
	sv.AudioURL = fmt.Sprintf("/station-voices/%d/audio", sv.ID)

	return nil
}

// User represents a system user with authentication credentials and role-based permissions.
type User struct {
	ID       int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Username string `gorm:"size:255;not null;uniqueIndex" json:"username"`
	FullName string `gorm:"size:255;not null" json:"full_name"`
	// PasswordHash is the bcrypt hashed password.
	PasswordHash string  `gorm:"size:255" json:"-"`
	Email        *string `gorm:"size:255;uniqueIndex" json:"email"`
	// Role defines the user's access level: admin, editor, or viewer.
	Role        UserRole       `gorm:"size:20;not null;default:'viewer';index" json:"role"`
	SuspendedAt *time.Time     `json:"suspended_at,omitempty"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at"`
	LastLoginAt *time.Time     `json:"last_login_at"`
	// LoginCount is the total number of successful logins.
	LoginCount int `gorm:"not null;default:0" json:"login_count"`
	// FailedLoginAttempts is the consecutive failed login attempts for account locking.
	FailedLoginAttempts int `gorm:"not null;default:0" json:"-"`
	// LockedUntil is the timestamp until which the account is locked after failed attempts.
	LockedUntil       *time.Time         `json:"locked_until,omitempty"`
	PasswordChangedAt *time.Time         `json:"password_changed_at,omitempty"`
	Metadata          *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
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
	ID        int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	StationID int64 `gorm:"not null;index" json:"station_id"`
	// Filename is the user-facing filename for the bulletin.
	Filename string `gorm:"size:255;not null" json:"filename"`
	// AudioFile is the generated audio filename, not a full path.
	// Files are stored in the output directory.
	AudioFile       string  `gorm:"size:500" json:"-"`
	DurationSeconds float64 `gorm:"not null;default:0" json:"duration_seconds"`
	FileSize        int64   `gorm:"not null;default:0" json:"file_size"`
	StoryCount      int     `gorm:"not null;default:0" json:"story_count"`
	// FilePurgedAt is when the audio file was cleaned up (nil means file still exists).
	FilePurgedAt *time.Time         `gorm:"index" json:"file_purged_at,omitempty"`
	Metadata     *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt    time.Time          `gorm:"index" json:"created_at"`

	// Relations are loaded by GORM when preloaded.
	Station *Station        `gorm:"foreignKey:StationID" json:"-"`
	Stories []BulletinStory `gorm:"foreignKey:BulletinID" json:"-"`

	// Computed fields are populated by AfterFind and not stored in the database.
	StationName string `gorm:"-" json:"station_name,omitempty"`
	AudioURL    string `gorm:"-" json:"audio_url,omitempty"`
}

// AfterFind populates computed fields from preloaded relations.
func (b *Bulletin) AfterFind(_ *gorm.DB) error {
	if b.Station != nil {
		b.StationName = b.Station.Name
	}

	// Only generate an audio URL if the file has not been purged.
	if b.FilePurgedAt == nil {
		b.AudioURL = fmt.Sprintf("/bulletins/%d/audio", b.ID)
	}

	return nil
}

// BulletinStory represents the relationship between bulletins and stories with join data.
type BulletinStory struct {
	ID         int64 `gorm:"primaryKey;autoIncrement" json:"id"`
	BulletinID int64 `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"bulletin_id"`
	StoryID    int64 `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"story_id"`
	// StoryOrder is the position of this story within the bulletin sequence.
	StoryOrder int       `gorm:"not null;default:0" json:"story_order"`
	CreatedAt  time.Time `json:"created_at"`

	// Relations are loaded by GORM when preloaded.
	Bulletin *Bulletin `gorm:"foreignKey:BulletinID" json:"-"`
	Story    *Story    `gorm:"foreignKey:StoryID" json:"-"`
}
