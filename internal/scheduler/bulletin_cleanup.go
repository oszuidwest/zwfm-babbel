package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// BulletinCleanupService handles automatic deletion of old bulletin audio files.
// Runs as a background service that periodically purges bulletin WAV files older than
// the configured retention period, while preserving database records as an audit trail.
type BulletinCleanupService struct {
	repo   *repository.BulletinRepository
	config *config.Config
	runner *runner
}

// NewBulletinCleanupService returns a stopped cleanup service.
// Call [BulletinCleanupService.Start] to begin daily purges.
func NewBulletinCleanupService(db *gorm.DB, cfg *config.Config) *BulletinCleanupService {
	s := &BulletinCleanupService{
		repo:   repository.NewBulletinRepository(db),
		config: cfg,
	}
	s.runner = newRunner("bulletin cleanup service", 24*time.Hour, 5*time.Minute, s.cleanup)
	return s
}

// Start runs cleanup immediately and then every 24 hours in a background
// goroutine.
func (s *BulletinCleanupService) Start() {
	logger.Info("Starting bulletin cleanup service (runs daily)", "retention", s.config.Audio.BulletinRetention)
	s.runner.Start()
}

// Stop gracefully shuts down the cleanup service.
func (s *BulletinCleanupService) Stop() {
	s.runner.Stop()
}

// cleanup performs the actual file purge logic.
func (s *BulletinCleanupService) cleanup(ctx context.Context) {
	logger.Info("Running bulletin file cleanup...")

	var purgedCount int
	var bytesFreed int64

	cutoff := time.Now().Add(-s.config.Audio.BulletinRetention)
	bulletins, err := s.repo.GetExpiredBulletins(ctx, cutoff)
	if err != nil {
		logger.Error("Failed to query expired bulletins", "error", err)
		return
	}

	outputDir := s.config.Audio.OutputPath

	for _, b := range bulletins {
		if b.AudioFile == "" {
			if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
				logger.Error("Failed to mark bulletin as purged", "bulletin_id", b.ID, "error", err)
			}
			continue
		}

		filePath := filepath.Join(outputDir, b.AudioFile)

		info, statErr := os.Stat(filePath)
		if statErr != nil && !os.IsNotExist(statErr) {
			logger.Error("Failed to stat bulletin file", "path", filePath, "error", statErr)
			continue
		}

		var fileBytes int64
		if info != nil {
			fileBytes = info.Size()
		}

		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			logger.Error("Failed to remove bulletin file", "path", filePath, "error", err)
			continue
		}

		if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
			logger.Error("Failed to mark bulletin as purged", "bulletin_id", b.ID, "error", err)
			continue
		}

		purgedCount++
		bytesFreed += fileBytes
	}

	orphansRemoved, orphanBytes := s.cleanOrphanedFiles(ctx)

	if purgedCount > 0 || orphansRemoved > 0 {
		logger.Info("Bulletin cleanup complete",
			"files_purged", purgedCount, "mb_freed", float64(bytesFreed)/1024/1024,
			"orphans_removed", orphansRemoved, "orphan_mb_freed", float64(orphanBytes)/1024/1024)
	}
}

// cleanOrphanedFiles removes files in the output directory that have no matching database record
// and are older than 1 hour (to avoid deleting files currently being generated).
func (s *BulletinCleanupService) cleanOrphanedFiles(ctx context.Context) (int, int64) {
	outputDir := s.config.Audio.OutputPath

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		logger.Error("Failed to read output directory", "path", outputDir, "error", err)
		return 0, 0
	}

	if len(entries) == 0 {
		return 0, 0
	}

	knownFiles, err := s.repo.GetAllAudioFiles(ctx)
	if err != nil {
		logger.Error("Failed to query audio files from database", "error", err)
		return 0, 0
	}

	knownSet := make(map[string]struct{}, len(knownFiles))
	for _, f := range knownFiles {
		knownSet[f] = struct{}{}
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	var removed int
	var bytesFreed int64

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if _, known := knownSet[entry.Name()]; known {
			continue
		}

		fullPath := filepath.Join(outputDir, entry.Name())

		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(oneHourAgo) {
			continue
		}

		fileBytes := info.Size()
		if err := os.Remove(fullPath); err != nil {
			logger.Error("Failed to remove orphaned file", "path", fullPath, "error", err)
			continue
		}

		removed++
		bytesFreed += fileBytes
	}

	return removed, bytesFreed
}
