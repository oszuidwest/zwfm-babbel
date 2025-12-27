// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import "time"

// BulletinResponse is the typed response for bulletin details
type BulletinResponse struct {
	ID          int64     `json:"id"`
	StationID   int64     `json:"station_id"`
	StationName string    `json:"station_name"`
	AudioURL    string    `json:"audio_url"`
	Filename    string    `json:"filename"`
	CreatedAt   time.Time `json:"created_at"`
	Duration    float64   `json:"duration_seconds"`
	FileSize    int64     `json:"file_size"`
	StoryCount  int       `json:"story_count"`
}

// StationRef is a minimal station reference
type StationRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// StoryRef is a minimal story reference
type StoryRef struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
}

// BulletinRef is a minimal bulletin reference
type BulletinRef struct {
	ID       int64  `json:"id"`
	Filename string `json:"filename"`
}

// BulletinStoryResponse is the typed response for bulletin-story relationships
type BulletinStoryResponse struct {
	ID         int64       `json:"id"`
	BulletinID int64       `json:"bulletin_id"`
	StoryID    int64       `json:"story_id"`
	StoryOrder int         `json:"story_order"`
	CreatedAt  time.Time   `json:"created_at"`
	Station    StationRef  `json:"station"`
	Story      StoryRef    `json:"story"`
	Bulletin   BulletinRef `json:"bulletin"`
}

// StoryBulletinHistoryResponse is the typed response for story bulletin history
type StoryBulletinHistoryResponse struct {
	BulletinResponse
	StoryOrder int       `json:"story_order"`
	IncludedAt time.Time `json:"included_at"`
}
