package scheduler

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// cleanInputLeftovers removes only old regular files from the directory Babbel
// owns for upload/TTS input. Never traverse directories or follow symlinks.
func (s *BulletinCleanupService) cleanInputLeftovers(now time.Time) error {
	dir := s.config.Audio.TempPath
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Error("Failed to read temporary audio directory", "path", dir, "error", err)
		return fmt.Errorf("read temporary audio directory: %w", err)
	}
	var cleanupErr error
	cutoff := now.Add(-processingMinAge)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := entry.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && (!info.Mode().IsRegular() || !info.ModTime().Before(cutoff)) {
			continue
		}
		if err == nil {
			err = os.Remove(path)
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue // The owning request cleaned its input during the sweep.
		}
		if err != nil {
			logger.Error("Failed to remove abandoned audio input", "path", path, "error", err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove abandoned audio input %s: %w", path, err))
			continue
		}
		logger.Info("Removed abandoned audio input", "path", path)
	}
	return cleanupErr
}
