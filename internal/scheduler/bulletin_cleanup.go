package scheduler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
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
	alerts notify.Alerter
}

// NewBulletinCleanupService returns a stopped cleanup service.
// Call [BulletinCleanupService.Start] to begin daily purges.
func NewBulletinCleanupService(db *gorm.DB, cfg *config.Config, alerts ...notify.Alerter) *BulletinCleanupService {
	var alertSink notify.Alerter
	if len(alerts) > 0 {
		alertSink = alerts[0]
	}
	s := &BulletinCleanupService{
		repo:   repository.NewBulletinRepository(db),
		config: cfg,
		alerts: alertSink,
	}
	s.runner = newRunner("bulletin cleanup service", 24*time.Hour, 5*time.Minute, s.cleanup, alertSink)
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

	cutoff := time.Now().Add(-s.config.Audio.BulletinRetention)
	bulletins, err := s.repo.GetExpiredBulletins(ctx, cutoff)
	if err != nil {
		logger.Error("Failed to query expired bulletins", "error", err)
		s.alertCleanup(ctx, err, notify.KindContinuous)
		return
	}
	stats, purgeErr := s.purgeExpiredBulletins(ctx, bulletins)
	orphansRemoved, orphanBytes, orphanErr := s.cleanOrphanedFiles(ctx)

	if stats.count > 0 || orphansRemoved > 0 {
		logger.Info("Bulletin cleanup complete",
			"files_purged", stats.count, "mb_freed", float64(stats.bytesFreed)/1024/1024,
			"orphans_removed", orphansRemoved, "orphan_mb_freed", float64(orphanBytes)/1024/1024)
	}
	if cleanupErr := errors.Join(purgeErr, orphanErr); cleanupErr != nil {
		s.alertCleanup(ctx, cleanupErr, notify.KindContinuous)
	} else if s.alerts != nil {
		s.alerts.Resolve(ctx, "scheduler:bulletin-cleanup", "Bulletin cleanup recovered", "Old and orphaned bulletin files can be cleaned again.")
	}
}

type purgeStats struct {
	count      int
	bytesFreed int64
}

func (s *BulletinCleanupService) purgeExpiredBulletins(
	ctx context.Context, bulletins []models.Bulletin,
) (purgeStats, error) {
	var stats purgeStats
	var cleanupErr error

	for _, b := range bulletins {
		if b.AudioFile == "" {
			if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("mark bulletin %d purged: %w", b.ID, err))
				logger.Error("Failed to mark bulletin as purged", "bulletin_id", b.ID, "error", err)
			}
			continue
		}

		filePath := filepath.Join(s.config.Audio.OutputPath, b.AudioFile)
		info, statErr := os.Stat(filePath)
		if statErr != nil && !os.IsNotExist(statErr) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stat bulletin %d: %w", b.ID, statErr))
			logger.Error("Failed to stat bulletin file", "path", filePath, "error", statErr)
			continue
		}

		var fileBytes int64
		if info != nil {
			fileBytes = info.Size()
		}
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove bulletin %d: %w", b.ID, err))
			logger.Error("Failed to remove bulletin file", "path", filePath, "error", err)
			continue
		}
		if err := s.repo.MarkFilePurged(ctx, b.ID); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("mark bulletin %d purged: %w", b.ID, err))
			logger.Error("Failed to mark bulletin as purged", "bulletin_id", b.ID, "error", err)
			continue
		}

		stats.count++
		stats.bytesFreed += fileBytes
	}

	return stats, cleanupErr
}

// cleanOrphanedFiles removes files in the output directory that have no matching database record
// and are older than 1 hour (to avoid deleting files currently being generated).
func (s *BulletinCleanupService) cleanOrphanedFiles(ctx context.Context) (int, int64, error) {
	outputDir := s.config.Audio.OutputPath

	entries, err := os.ReadDir(outputDir)
	if err != nil {
		logger.Error("Failed to read output directory", "path", outputDir, "error", err)
		if s.alerts != nil {
			s.alerts.Alert(ctx, notify.Event{
				Key: "storage:bulletin-output", Summary: "Bulletin output directory is unreadable",
				Details: fmt.Sprintf("%s: %v", outputDir, err), Kind: notify.KindImmediate,
			})
		}
		return 0, 0, err
	}
	if s.alerts != nil {
		s.alerts.Resolve(ctx, "storage:bulletin-output", "Bulletin output directory recovered", "The output directory is readable again.")
	}

	if len(entries) == 0 {
		return 0, 0, nil
	}

	knownFiles, err := s.repo.GetAllAudioFiles(ctx)
	if err != nil {
		logger.Error("Failed to query audio files from database", "error", err)
		return 0, 0, err
	}

	knownSet := make(map[string]struct{}, len(knownFiles))
	for _, f := range knownFiles {
		knownSet[f] = struct{}{}
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	var removed int
	var bytesFreed int64
	var cleanupErr error

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
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("stat orphan %s: %w", fullPath, err))
			continue
		}
		if info.ModTime().After(oneHourAgo) {
			continue
		}

		fileBytes := info.Size()
		if err := os.Remove(fullPath); err != nil {
			logger.Error("Failed to remove orphaned file", "path", fullPath, "error", err)
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove orphan %s: %w", fullPath, err))
			continue
		}

		removed++
		bytesFreed += fileBytes
	}

	return removed, bytesFreed, cleanupErr
}

func (s *BulletinCleanupService) alertCleanup(ctx context.Context, err error, kind notify.Kind) {
	if s.alerts != nil {
		s.alerts.Alert(ctx, notify.Event{
			Key: "scheduler:bulletin-cleanup", Summary: "Bulletin cleanup repeatedly fails",
			Details: err.Error(), Kind: kind,
		})
	}
}
