package scheduler

import (
	"context"
	"os"
	"path/filepath"
	"sync"
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
	// repo provides access to bulletin data for cleanup queries
	repo repository.BulletinRepository
	// config holds the application configuration including retention settings
	config *config.Config
	// ticker controls the daily execution schedule
	ticker *time.Ticker
	// done channel enables graceful shutdown signaling
	done chan bool
	// stopOnce ensures Stop() can only be called once, preventing double-stop race conditions
	stopOnce sync.Once
}

// NewBulletinCleanupService creates a new background service for bulletin file cleanup.
// The service must be started with [BulletinCleanupService.Start] to begin operations.
func NewBulletinCleanupService(db *gorm.DB, cfg *config.Config) *BulletinCleanupService {
	return &BulletinCleanupService{
		repo:   repository.NewBulletinRepository(db),
		config: cfg,
		done:   make(chan bool),
	}
}

// Start begins the background cleanup service with immediate execution and daily intervals.
// The service runs in a separate goroutine and can be stopped with [BulletinCleanupService.Stop].
func (s *BulletinCleanupService) Start() {
	logger.Info("Starting bulletin cleanup service (retention: %s, runs daily)", s.config.Audio.BulletinRetention)

	// Run immediately on start with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	s.cleanup(ctx)

	// Then run every 24 hours
	s.ticker = time.NewTicker(24 * time.Hour)

	go func() {
		for {
			select {
			case <-s.ticker.C:
				func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					s.cleanup(ctx)
				}()
			case <-s.done:
				return
			}
		}
	}()
}

// Stop gracefully shuts down the cleanup service.
// Uses sync.Once to prevent double-stop race conditions and a timeout to prevent deadlock.
func (s *BulletinCleanupService) Stop() {
	s.stopOnce.Do(func() {
		logger.Info("Stopping bulletin cleanup service")
		select {
		case s.done <- true:
		case <-time.After(5 * time.Second):
			logger.Info("Bulletin cleanup service shutdown timeout")
		}
		if s.ticker != nil {
			s.ticker.Stop()
		}
	})
}

// cleanup performs the actual file purge logic.
func (s *BulletinCleanupService) cleanup(ctx context.Context) {
	logger.Info("Running bulletin file cleanup...")

	var purgedCount int
	var bytesFreed int64

	// Purge expired bulletin files
	cutoff := time.Now().Add(-s.config.Audio.BulletinRetention)
	bulletins, err := s.repo.GetExpiredBulletins(ctx, cutoff)
	if err != nil {
		logger.Error("Failed to query expired bulletins: %v", err)
		return
	}

	outputDir := s.config.Audio.OutputPath

	for _, b := range bulletins {
		if b.AudioFile == "" {
			// No file to delete, just mark as purged
			if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
				logger.Error("Failed to mark bulletin %d as purged: %v", b.ID, err)
			}
			continue
		}

		// AudioFile is stored as a filename, not a full path
		filePath := filepath.Join(outputDir, b.AudioFile)

		info, statErr := os.Stat(filePath)
		if statErr != nil && !os.IsNotExist(statErr) {
			logger.Error("Failed to stat bulletin file %s: %v", filePath, statErr)
			continue
		}

		var fileBytes int64
		if info != nil {
			fileBytes = info.Size()
		}

		// Remove the file (ignore "not found" — file may already be gone)
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			logger.Error("Failed to remove bulletin file %s: %v", filePath, err)
			continue
		}

		if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
			logger.Error("Failed to mark bulletin %d as purged: %v", b.ID, err)
			continue
		}

		purgedCount++
		bytesFreed += fileBytes
	}

	// Clean up orphaned files in output directory
	orphansRemoved, orphanBytes := s.cleanOrphanedFiles(ctx)

	if purgedCount > 0 || orphansRemoved > 0 {
		logger.Info("Bulletin cleanup complete: %d files purged (%.1f MB freed), %d orphans removed (%.1f MB freed)",
			purgedCount, float64(bytesFreed)/1024/1024,
			orphansRemoved, float64(orphanBytes)/1024/1024)
	}
}

// cleanOrphanedFiles removes files in the output directory that have no matching database record
// and are older than 1 hour (to avoid deleting files currently being generated).
func (s *BulletinCleanupService) cleanOrphanedFiles(ctx context.Context) (int, int64) {
	outputDir := s.config.Audio.OutputPath

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		logger.Error("Failed to read output directory %s: %v", outputDir, err)
		return 0, 0
	}

	if len(entries) == 0 {
		return 0, 0
	}

	// Get all known audio files from database
	knownFiles, err := s.repo.GetAllAudioFiles(ctx)
	if err != nil {
		logger.Error("Failed to query audio files from database: %v", err)
		return 0, 0
	}

	// Build a set of known filenames (DB stores filenames, not full paths)
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

		// Compare using filename only, matching the DB storage format
		if _, known := knownSet[entry.Name()]; known {
			continue
		}

		fullPath := filepath.Join(outputDir, entry.Name())

		// Only remove files older than 1 hour to avoid race with active generation
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(oneHourAgo) {
			continue
		}

		fileBytes := info.Size()
		if err := os.Remove(fullPath); err != nil {
			logger.Error("Failed to remove orphaned file %s: %v", fullPath, err)
			continue
		}

		removed++
		bytesFreed += fileBytes
	}

	return removed, bytesFreed
}
