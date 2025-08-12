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

// GetStoryRelativePath returns the relative path from app root for storing a story.
func GetStoryRelativePath(config *config.Config, storyID int) string {
	rel, err := filepath.Rel(config.Audio.AppRoot, config.Audio.ProcessedPath)
	if err != nil {
		rel = "audio/processed"
	}
	return filepath.Join(rel, GetStoryFilename(storyID))
}

// GetJingleRelativePath returns the relative path from app root for storing a jingle.
func GetJingleRelativePath(config *config.Config, stationID, voiceID int) string {
	rel, err := filepath.Rel(config.Audio.AppRoot, config.Audio.ProcessedPath)
	if err != nil {
		rel = "audio/processed"
	}
	return filepath.Join(rel, GetJingleFilename(stationID, voiceID))
}

// GenerateBulletinPaths returns both absolute and relative paths for a bulletin using a single timestamp.
// This ensures consistency between file creation and database storage.
// Returns (absolutePath, relativePath) where:
// - absolutePath is used for file creation
// - relativePath is used for database storage
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
