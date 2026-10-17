package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// ProcessingDirSuffix ends the name of every per-request conversion
// directory, so cleanup of abandoned conversions can match on it.
const ProcessingDirSuffix = ".processing"

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
	return fmt.Sprintf("bulletin_%d_%s.wav", stationID, timestamp.Format("20060102_150405.000000000"))
}

// GenerateBulletinPaths returns the absolute write path for a bulletin.
func GenerateBulletinPaths(config *config.Config, stationID int64, timestamp time.Time) string {
	return BulletinPath(config, BulletinFilename(stationID, timestamp))
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

// ProcessingPath creates a "<name>_*.processing" directory beside finalPath
// and returns the path inside it to convert to, plus a func that removes the
// directory. Converting beside the final file keeps the rename atomic and the
// ".wav" name selects the WAV muxer. A directory per request keeps concurrent
// requests for the same file from overwriting or removing each other's
// output, and the converter creates the file, so its mode follows the umask.
func ProcessingPath(finalPath, name string) (string, func(), error) {
	dir, err := os.MkdirTemp(filepath.Dir(finalPath), name+"_*"+ProcessingDirSuffix)
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		if err := os.RemoveAll(dir); err != nil {
			logger.Error("Failed to remove audio processing directory", "path", dir, "error", err)
		}
	}
	return filepath.Join(dir, filepath.Base(finalPath)), cleanup, nil
}
