// Package utils provides path utilities for audio file construction
package utils

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// GetStoryPath returns the full path for a story audio file
func GetStoryPath(config *config.Config, storyID int) string {
	return filepath.Join(config.Audio.ProcessedPath, fmt.Sprintf("story_%d.wav", storyID))
}

// GetJinglePath returns the full path for a station-voice jingle file
func GetJinglePath(config *config.Config, stationID, voiceID int) string {
	return filepath.Join(config.Audio.ProcessedPath, fmt.Sprintf("station_%d_voice_%d_jingle.wav", stationID, voiceID))
}

// GetBulletinPath returns the full path for a bulletin output file
func GetBulletinPath(config *config.Config, stationID int, timestamp time.Time) string {
	return filepath.Join(config.Audio.OutputPath, fmt.Sprintf("bulletin_%d_%s.wav", stationID, timestamp.Format("20060102_150405")))
}

// GetTempBulletinDir returns a temporary directory path for bulletin creation
func GetTempBulletinDir(config *config.Config, uuid string) string {
	return filepath.Join(config.Audio.TempPath, uuid)
}

// GetJingleFilename returns just the filename for a station-voice jingle file
func GetJingleFilename(stationID, voiceID int) string {
	return fmt.Sprintf("station_%d_voice_%d_jingle.wav", stationID, voiceID)
}

// GetStoryFilename returns just the filename for a story audio file
func GetStoryFilename(storyID int) string {
	return fmt.Sprintf("story_%d.wav", storyID)
}
