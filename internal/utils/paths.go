package utils

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// StoryFilename returns the canonical processed-audio filename for storyID.
func StoryFilename(storyID int64) string {
	return fmt.Sprintf("story_%d.wav", storyID)
}

// JingleFilename returns the canonical jingle filename for a station/voice pair.
func JingleFilename(stationID, voiceID int64) string {
	return fmt.Sprintf("station_%d_voice_%d_jingle.wav", stationID, voiceID)
}

// BulletinFilename returns the output filename for a generated station bulletin.
func BulletinFilename(stationID int64, timestamp time.Time) string {
	return fmt.Sprintf("bulletin_%d_%s.wav", stationID, timestamp.Format("20060102_150405"))
}

// GenerateBulletinPaths returns the absolute write path for a bulletin.
func GenerateBulletinPaths(config *config.Config, stationID int64, timestamp time.Time) string {
	return filepath.Join(config.Audio.OutputPath, BulletinFilename(stationID, timestamp))
}

// StoryPath returns the absolute filesystem path for a processed story file.
func StoryPath(config *config.Config, storyID int64) string {
	return filepath.Join(config.Audio.ProcessedPath, StoryFilename(storyID))
}

// JinglePath returns the absolute filesystem path for a station-voice jingle.
func JinglePath(config *config.Config, stationID, voiceID int64) string {
	return filepath.Join(config.Audio.ProcessedPath, JingleFilename(stationID, voiceID))
}

// BulletinPath returns the absolute filesystem path for a bulletin filename.
func BulletinPath(config *config.Config, filename string) string {
	return filepath.Join(config.Audio.OutputPath, filename)
}
