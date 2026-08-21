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
	ID                 int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	Name               string `gorm:"size:255;not null;uniqueIndex" json:"name"`
	MaxStoriesPerBlock int    `gorm:"not null;default:5" json:"max_stories_per_block"`
	// PauseSeconds is the pause duration between stories. No gorm default:
	// the handler resolves omitted values, and a default tag would make GORM
	// drop an explicit 0 from the INSERT so the database default wins.
	PauseSeconds float64   `gorm:"not null" json:"pause_seconds"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	StationVoices []StationVoice `gorm:"foreignKey:StationID" json:"-"`
	Bulletins     []Bulletin     `gorm:"foreignKey:StationID" json:"-"`
}

// Story represents a news story with scheduling and audio.
type Story struct {
	ID              int64       `gorm:"primaryKey;autoIncrement" json:"id"`
	Title           string      `gorm:"size:500;not null" json:"title"`
	Text            string      `gorm:"type:text" json:"text"`
	VoiceID         *int64      `gorm:"index" json:"voice_id"`
	AudioFile       string      `gorm:"size:500" json:"audio_file"`
	DurationSeconds *float64    `json:"duration_seconds"`
	Status          StoryStatus `gorm:"size:20;not null;default:'draft';index" json:"status"`
	StartDate       time.Time   `gorm:"not null;index" json:"start_date"`
	EndDate         time.Time   `gorm:"not null;index" json:"end_date"`
	Weekdays        Weekdays    `gorm:"not null;default:127;index" json:"weekdays"`
	// IsBreaking takes priority over fair rotation.
	IsBreaking bool               `gorm:"not null;default:false;index" json:"is_breaking"`
	Metadata   *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
	DeletedAt  gorm.DeletedAt     `gorm:"index" json:"deleted_at"`

	Voice *Voice `gorm:"foreignKey:VoiceID" json:"-"`

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

// Voice represents a text-to-speech voice configuration.
type Voice struct {
	ID                int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Name              string    `gorm:"size:255;not null;uniqueIndex" json:"name"`
	ElevenLabsVoiceID *string   `gorm:"column:elevenlabs_voice_id;size:255" json:"elevenlabs_voice_id,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	Stories       []Story        `gorm:"foreignKey:VoiceID" json:"-"`
	StationVoices []StationVoice `gorm:"foreignKey:VoiceID" json:"-"`
}

// StationVoice represents the many-to-many relationship between stations and voices.
type StationVoice struct {
	ID        int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	StationID int64  `gorm:"not null;uniqueIndex:idx_station_voice" json:"station_id"`
	VoiceID   int64  `gorm:"not null;uniqueIndex:idx_station_voice" json:"voice_id"`
	AudioFile string `gorm:"size:500" json:"audio_file"`
	// MixPoint is where story audio enters the jingle, in seconds.
	MixPoint  float64   `gorm:"not null;default:0" json:"mix_point"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Station *Station `gorm:"foreignKey:StationID" json:"-"`
	Voice   *Voice   `gorm:"foreignKey:VoiceID" json:"-"`

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
	ID                  int64              `gorm:"primaryKey;autoIncrement" json:"id"`
	Username            string             `gorm:"size:255;not null;uniqueIndex" json:"username"`
	FullName            string             `gorm:"size:255;not null" json:"full_name"`
	PasswordHash        string             `gorm:"size:255" json:"-"`
	Email               *string            `gorm:"size:255;uniqueIndex" json:"email"`
	Role                UserRole           `gorm:"size:20;not null;default:'viewer';index" json:"role"`
	SuspendedAt         *time.Time         `json:"suspended_at,omitempty"`
	DeletedAt           gorm.DeletedAt     `gorm:"index" json:"deleted_at"`
	LastLoginAt         *time.Time         `json:"last_login_at"`
	LoginCount          int                `gorm:"not null;default:0" json:"login_count"`
	FailedLoginAttempts int                `gorm:"not null;default:0" json:"-"`
	LockedUntil         *time.Time         `json:"locked_until,omitempty"`
	PasswordChangedAt   *time.Time         `json:"password_changed_at,omitempty"`
	Metadata            *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
}

// UserRole represents a user's permission level.
type UserRole string

// RBAC roles.
const (
	RoleAdmin  UserRole = "admin"
	RoleEditor UserRole = "editor"
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

// Bulletin represents a completed audio bulletin generated from multiple stories.
type Bulletin struct {
	ID        int64  `gorm:"primaryKey;autoIncrement" json:"id"`
	StationID int64  `gorm:"not null;index" json:"station_id"`
	Filename  string `gorm:"size:255;not null" json:"filename"`
	// AudioFile is relative to the output directory.
	AudioFile       string  `gorm:"size:500" json:"-"`
	DurationSeconds float64 `gorm:"not null;default:0" json:"duration_seconds"`
	FileSize        int64   `gorm:"not null;default:0" json:"file_size"`
	StoryCount      int     `gorm:"not null;default:0" json:"story_count"`
	// FilePurgedAt is when the audio file was cleaned up (nil means file still exists).
	FilePurgedAt *time.Time         `gorm:"index" json:"file_purged_at,omitempty"`
	Metadata     *datatypes.JSONMap `gorm:"type:json" json:"metadata,omitempty"`
	CreatedAt    time.Time          `gorm:"index" json:"created_at"`

	Station *Station        `gorm:"foreignKey:StationID" json:"-"`
	Stories []BulletinStory `gorm:"foreignKey:BulletinID" json:"-"`

	StationName string `gorm:"-" json:"station_name,omitempty"`
	AudioURL    string `gorm:"-" json:"audio_url,omitempty"`
}

// BulletinJobStatus describes asynchronous bulletin generation progress.
type BulletinJobStatus string

const (
	BulletinJobQueued    BulletinJobStatus = "queued"
	BulletinJobRunning   BulletinJobStatus = "running"
	BulletinJobSucceeded BulletinJobStatus = "succeeded"
	BulletinJobFailed    BulletinJobStatus = "failed"
)

// BulletinJob is a durable asynchronous bulletin-generation request.
type BulletinJob struct {
	ID          int64             `gorm:"primaryKey;autoIncrement" json:"id"`
	StationID   int64             `gorm:"not null;index" json:"station_id"`
	TargetDate  time.Time         `gorm:"type:date;not null" json:"target_date"`
	Status      BulletinJobStatus `gorm:"size:20;not null;index" json:"status"`
	Attempt     int               `gorm:"not null;default:0" json:"attempt"`
	BulletinID  *int64            `gorm:"index" json:"bulletin_id"`
	ErrorCode   string            `gorm:"size:100;not null;default:''" json:"error_code,omitempty"`
	ErrorDetail string            `gorm:"size:1000;not null;default:''" json:"error_detail,omitempty"`
	StartedAt   *time.Time        `json:"started_at"`
	CompletedAt *time.Time        `json:"completed_at"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
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
	ID         int64     `gorm:"primaryKey;autoIncrement" json:"id"`
	BulletinID int64     `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"bulletin_id"`
	StoryID    int64     `gorm:"not null;index;uniqueIndex:idx_bulletin_story" json:"story_id"`
	StoryOrder int       `gorm:"not null;default:0" json:"story_order"`
	CreatedAt  time.Time `json:"created_at"`

	Bulletin *Bulletin `gorm:"foreignKey:BulletinID" json:"-"`
	Story    *Story    `gorm:"foreignKey:StoryID" json:"-"`
}
