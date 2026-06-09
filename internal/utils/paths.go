package utils

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const defaultAudioOutputPath = "audio/output"

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

// GenerateBulletinPaths returns the write path and app-root-relative storage
// path for a bulletin.
func GenerateBulletinPaths(config *config.Config, stationID int64, timestamp time.Time) (string, string) {
	if config == nil {
		logger.Error("GenerateBulletinPaths called with nil config - this is a programming error")
		return "", ""
	}
	filename := BulletinFilename(stationID, timestamp)

	absolutePath := filepath.Join(config.Audio.OutputPath, filename)

	rel, err := filepath.Rel(config.Audio.AppRoot, config.Audio.OutputPath)
	if err != nil {
		logger.Warn("Failed to compute relative path for bulletin output, using default", "error", err)
		rel = defaultAudioOutputPath
	}
	relativePath := filepath.Join(rel, filename)

	return absolutePath, relativePath
}

// StoryPath returns the absolute filesystem path for a processed story file.
func StoryPath(config *config.Config, storyID int64) string {
	if config == nil {
		logger.Error("StoryPath called with nil config - this is a programming error")
		return ""
	}
	return filepath.Join(config.Audio.ProcessedPath, StoryFilename(storyID))
}

// JinglePath returns the absolute filesystem path for a station-voice jingle.
func JinglePath(config *config.Config, stationID, voiceID int64) string {
	if config == nil {
		logger.Error("JinglePath called with nil config - this is a programming error")
		return ""
	}
	return filepath.Join(config.Audio.ProcessedPath, JingleFilename(stationID, voiceID))
}

// TempBulletinDir returns a temporary directory path for bulletin creation.
func TempBulletinDir(config *config.Config, uuid string) string {
	if config == nil {
		logger.Error("TempBulletinDir called with nil config - this is a programming error")
		return ""
	}
	return filepath.Join(config.Audio.TempPath, uuid)
}

// BulletinPath returns the absolute filesystem path for a bulletin filename.
func BulletinPath(config *config.Config, filename string) string {
	if config == nil {
		logger.Error("BulletinPath called with nil config - this is a programming error")
		return ""
	}
	return filepath.Join(config.Audio.OutputPath, filename)
}
