package handlers

import "time"

// BulletinResponse is the typed response for bulletin details
type BulletinResponse struct {
	ID          int       `json:"id"`
	StationID   int       `json:"station_id"`
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
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// StoryRef is a minimal story reference
type StoryRef struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

// BulletinRef is a minimal bulletin reference
type BulletinRef struct {
	ID       int    `json:"id"`
	Filename string `json:"filename"`
}

// BulletinStoryResponse is the typed response for bulletin-story relationships
type BulletinStoryResponse struct {
	ID         int         `json:"id"`
	BulletinID int         `json:"bulletin_id"`
	StoryID    int         `json:"story_id"`
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
