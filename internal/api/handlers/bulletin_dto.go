// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import "time"

// BulletinResponse is the typed response for bulletin details.
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
