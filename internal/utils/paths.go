// Package utils provides shared utility functions for HTTP handlers, database operations, and queries.
package utils

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// GetStoryFilename returns the standardized filename for a story audio file.
func GetStoryFilename(storyID int) string {
	return fmt.Sprintf("story_%d.wav", storyID)
}

// GetJingleFilename returns the standardized filename for a station-voice jingle file.
func GetJingleFilename(stationID, voiceID int) string {
	return fmt.Sprintf("station_%d_voice_%d_jingle.wav", stationID, voiceID)
}

// GetBulletinFilename returns the timestamped filename for a bulletin output file.
func GetBulletinFilename(stationID int, timestamp time.Time) string {
	return fmt.Sprintf("bulletin_%d_%s.wav", stationID, timestamp.Format("20060102_150405"))
}

// GenerateBulletinPaths returns both absolute and relative paths for a bulletin.
// Returns (absolutePath, relativePath) where absolutePath includes the full system path
// and relativePath is relative to the upload directory.
func GenerateBulletinPaths(config *config.Config, stationID int, timestamp time.Time) (string, string) {
	filename := GetBulletinFilename(stationID, timestamp)

	// Generate absolute path for file creation
	absolutePath := filepath.Join(config.Audio.OutputPath, filename)

	// Generate relative path for database storage
	rel, err := filepath.Rel(config.Audio.AppRoot, config.Audio.OutputPath)
	if err != nil {
		rel = "audio/output"
	}
	relativePath := filepath.Join(rel, filename)

	return absolutePath, relativePath
}

// GetStoryPath returns the absolute filesystem path for a story audio file.
func GetStoryPath(config *config.Config, storyID int) string {
	return filepath.Join(config.Audio.ProcessedPath, GetStoryFilename(storyID))
}

// GetJinglePath returns the absolute filesystem path for a jingle file.
func GetJinglePath(config *config.Config, stationID, voiceID int) string {
	return filepath.Join(config.Audio.ProcessedPath, GetJingleFilename(stationID, voiceID))
}

// GetTempBulletinDir returns a temporary directory path for bulletin creation.
func GetTempBulletinDir(config *config.Config, uuid string) string {
	return filepath.Join(config.Audio.TempPath, uuid)
}
