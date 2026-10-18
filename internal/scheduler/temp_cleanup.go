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

// cleanInputLeftovers removes regular files older than processingMinAge from
// the directory Babbel owns for upload and TTS input. It never enters
// directories or follows symlinks, and refuses a temporary directory that is
// also a persistent audio directory, whose files are published audio.
func (s *BulletinCleanupService) cleanInputLeftovers(now time.Time) error {
	dir := s.config.Audio.TempPath
	if tempInfo, err := os.Stat(dir); err == nil {
		for _, persistent := range []string{s.config.Audio.ProcessedPath, s.config.Audio.OutputPath} {
			if info, err := os.Stat(persistent); err == nil && os.SameFile(tempInfo, info) {
				logger.Error("Temporary audio directory is a persistent audio directory; not sweeping it", "path", dir, "persistent", persistent)
				return fmt.Errorf("temporary audio directory %s is also %s; not sweeping it", dir, persistent)
			}
		}
	}
	return sweepOldEntries(dir, "temporary audio", "audio input", now, func(entry fs.DirEntry) bool {
		return entry.Type().IsRegular()
	})
}

// sweepOldEntries removes the entries of dir that match and are older than
// processingMinAge, logging each removal and failure. An entry whose type
// changed since ReadDir is skipped, only directories are removed recursively
// (os.RemoveAll does not follow symlinks inside them), and an entry that
// vanishes during the sweep is not an error.
func sweepOldEntries(dir, dirDesc, entryDesc string, now time.Time, match func(fs.DirEntry) bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Error("Failed to read "+dirDesc+" directory", "path", dir, "error", err)
		return fmt.Errorf("read %s directory: %w", dirDesc, err)
	}

	cutoff := now.Add(-processingMinAge)
	var cleanupErr error
	for _, entry := range entries {
		if !match(entry) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		info, err := processingEntryInfo(entry)
		if errors.Is(err, fs.ErrNotExist) {
			continue // The owning request removed it after ReadDir.
		}
		if err != nil {
			logger.Error("Failed to stat "+entryDesc, "path", path, "error", err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stat %s %s: %w", entryDesc, path, err))
			continue
		}
		if info.Mode().Type() != entry.Type() || !info.ModTime().Before(cutoff) {
			continue // Replaced since ReadDir, or not old enough.
		}
		remove := os.Remove
		if info.IsDir() {
			remove = os.RemoveAll // Only matched conversion directories.
		}
		if err := remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Error("Failed to remove "+entryDesc, "path", path, "error", err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s %s: %w", entryDesc, path, err))
			continue
		}
		logger.Info("Removed abandoned "+entryDesc, "path", path)
	}
	return cleanupErr
}
