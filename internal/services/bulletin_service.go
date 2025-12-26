// Package services provides domain services for the Babbel API.
package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// BulletinService handles bulletin generation and retrieval operations.
type BulletinService struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
}

// NewBulletinService creates a new bulletin service instance.
func NewBulletinService(db *sqlx.DB, audioSvc *audio.Service, config *config.Config) *BulletinService {
	return &BulletinService{
		db:       db,
		audioSvc: audioSvc,
		config:   config,
	}
}

// BulletinInfo contains metadata about a generated bulletin.
type BulletinInfo struct {
	ID           int64
	Station      models.Station
	Stories      []models.Story
	BulletinPath string
	Duration     float64
	FileSize     int64
	CreatedAt    time.Time
}

// Create generates a new bulletin for the specified station and date.
// It selects appropriate stories, generates the audio file, and saves the bulletin record.
func (s *BulletinService) Create(ctx context.Context, stationID int, targetDate time.Time) (*BulletinInfo, error) {
	// Validate station exists and fetch details
	station, err := s.validateAndFetchStation(ctx, stationID)
	if err != nil {
		return nil, err
	}

	// Get stories for the date
	stories, err := s.GetStoriesForDate(ctx, stationID, targetDate, station.MaxStoriesPerBlock)
	if err != nil {
		return nil, err
	}

	if len(stories) == 0 {
		return nil, ErrNoStoriesAvailable
	}

	// Generate audio file
	bulletinPath, err := s.generateBulletinAudio(ctx, station, stories)
	if err != nil {
		return nil, err
	}

	// Get file metadata
	fileSize := s.getFileSize(bulletinPath)
	totalDuration := s.calculateBulletinDuration(station, stories)

	// Persist bulletin to database
	bulletinID, err := s.saveBulletinToDatabase(ctx, stationID, bulletinPath, totalDuration, fileSize, stories)
	if err != nil {
		return nil, err
	}

	return &BulletinInfo{
		ID:           bulletinID,
		Station:      *station,
		Stories:      stories,
		BulletinPath: bulletinPath,
		Duration:     totalDuration,
		FileSize:     fileSize,
		CreatedAt:    time.Now(),
	}, nil
}

// validateAndFetchStation validates that a station exists and returns its details.
func (s *BulletinService) validateAndFetchStation(ctx context.Context, stationID int) (*models.Station, error) {
	var station models.Station
	err := s.db.GetContext(ctx, &station, "SELECT * FROM stations WHERE id = ?", stationID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: station not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to fetch station: %v", ErrDatabaseError, err)
	}
	return &station, nil
}

// generateBulletinAudio creates the audio file for a bulletin and returns its path.
func (s *BulletinService) generateBulletinAudio(ctx context.Context, station *models.Station, stories []models.Story) (string, error) {
	// Generate consistent paths using single timestamp
	timestamp := time.Now()
	bulletinPath, _ := utils.GenerateBulletinPaths(s.config, station.ID, timestamp)

	// Create bulletin using the generated absolute path
	createdPath, err := s.audioSvc.CreateBulletin(ctx, station, stories, bulletinPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrAudioProcessingFailed, err)
	}

	// Verify the paths match (should always be true with unified function)
	if createdPath != bulletinPath {
		log.Printf("WARNING: Path mismatch - created: %s, expected: %s", createdPath, bulletinPath)
	}

	return bulletinPath, nil
}

// getFileSize safely retrieves the file size, returning 0 if stat fails.
func (s *BulletinService) getFileSize(path string) int64 {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fileInfo.Size()
}

// calculateBulletinDuration computes the total duration including stories, pauses, and mix points.
func (s *BulletinService) calculateBulletinDuration(station *models.Station, stories []models.Story) float64 {
	// Calculate total duration of all stories
	var storiesDuration float64
	for _, story := range stories {
		if story.DurationSeconds != nil {
			storiesDuration += *story.DurationSeconds
		}
	}

	// Add pauses between stories
	if station.PauseSeconds > 0 && len(stories) > 1 {
		storiesDuration += station.PauseSeconds * float64(len(stories)-1)
	}

	// Add mix point delay (when voice starts over jingle)
	var mixPointDelay float64
	if len(stories) > 0 && stories[0].VoiceMixPoint > 0 {
		mixPointDelay = stories[0].VoiceMixPoint
	}

	// Total duration = stories duration + pauses + mix point delay
	return storiesDuration + mixPointDelay
}

// saveBulletinToDatabase persists the bulletin record and story relationships in a transaction.
func (s *BulletinService) saveBulletinToDatabase(ctx context.Context, stationID int, bulletinPath string, duration float64, fileSize int64, stories []models.Story) (int64, error) {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to begin transaction: %v", ErrDatabaseError, err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			logger.Error("Failed to rollback transaction: %v", err)
		}
	}()

	// Insert bulletin record
	bulletinID, err := s.insertBulletinRecord(ctx, tx, stationID, bulletinPath, duration, fileSize, len(stories))
	if err != nil {
		return 0, err
	}

	// Link stories to bulletin
	if err := s.linkStoriesToBulletin(ctx, tx, bulletinID, stories); err != nil {
		return 0, err
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("%w: failed to commit transaction: %v", ErrDatabaseError, err)
	}

	return bulletinID, nil
}

// insertBulletinRecord creates the bulletin database record.
func (s *BulletinService) insertBulletinRecord(ctx context.Context, tx *sqlx.Tx, stationID int, bulletinPath string, duration float64, fileSize int64, storyCount int) (int64, error) {
	result, err := tx.ExecContext(ctx, `
		INSERT INTO bulletins (station_id, filename, audio_file, duration_seconds, file_size, story_count)
		VALUES (?, ?, ?, ?, ?, ?)`,
		stationID,
		filepath.Base(bulletinPath),
		filepath.Base(bulletinPath),
		duration,
		fileSize,
		storyCount,
	)
	if err != nil {
		return 0, fmt.Errorf("%w: failed to save bulletin: %v", ErrDatabaseError, err)
	}

	bulletinID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%w: failed to get bulletin ID: %v", ErrDatabaseError, err)
	}

	return bulletinID, nil
}

// linkStoriesToBulletin creates bulletin-story relationship records.
func (s *BulletinService) linkStoriesToBulletin(ctx context.Context, tx *sqlx.Tx, bulletinID int64, stories []models.Story) error {
	for i, story := range stories {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO bulletin_stories (bulletin_id, story_id, story_order) VALUES (?, ?, ?)",
			bulletinID, story.ID, i,
		)
		if err != nil {
			return fmt.Errorf("%w: failed to link story %d to bulletin: %v", ErrDatabaseError, story.ID, err)
		}
	}
	return nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (s *BulletinService) GetLatest(ctx context.Context, stationID int, maxAge *time.Duration) (*models.Bulletin, error) {
	var bulletin models.Bulletin

	// Build query with optional age filter
	query := `
		SELECT b.*, s.name as station_name
		FROM bulletins b
		JOIN stations s ON b.station_id = s.id
		WHERE b.station_id = ?`

	args := []interface{}{stationID}

	// Add age filter if specified
	if maxAge != nil {
		query += ` AND b.created_at >= ?`
		args = append(args, time.Now().Add(-*maxAge))
	}

	query += ` ORDER BY b.created_at DESC LIMIT 1`

	err := s.db.GetContext(ctx, &bulletin, query, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: no bulletin found for station", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to fetch bulletin: %v", ErrDatabaseError, err)
	}

	return &bulletin, nil
}

// GetStoriesForDate retrieves eligible stories for bulletin generation on a specific date.
// Stories must be active, have audio, match the station's voice configuration, and be scheduled for the weekday.
func (s *BulletinService) GetStoriesForDate(ctx context.Context, stationID int, date time.Time, limit int) ([]models.Story, error) {
	weekdayColumn := getWeekdayColumn(date.Weekday())

	var stories []models.Story
	query := fmt.Sprintf(`
		SELECT s.*, v.name as voice_name, sv.audio_file as voice_jingle, sv.mix_point as voice_mix_point
		FROM stories s
		JOIN voices v ON s.voice_id = v.id
		JOIN station_voices sv ON sv.station_id = ? AND sv.voice_id = s.voice_id
		WHERE s.deleted_at IS NULL
		AND s.audio_file IS NOT NULL
		AND s.audio_file != ''
		AND s.start_date <= ?
		AND s.end_date >= ?
		AND s.%s = 1
		ORDER BY RAND()
		LIMIT ?`, weekdayColumn)

	err := s.db.SelectContext(ctx, &stories, query, stationID, date, date, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch stories: %v", ErrDatabaseError, err)
	}

	return stories, nil
}

// ParseTargetDate parses a date string in YYYY-MM-DD format or returns the current date if empty.
func ParseTargetDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Now(), nil
	}
	parsedDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid date format (expected YYYY-MM-DD)", ErrInvalidInput)
	}
	return parsedDate, nil
}

// getWeekdayColumn returns the corresponding database column name for a time.Weekday.
func getWeekdayColumn(weekday time.Weekday) string {
	switch weekday {
	case time.Monday:
		return "monday"
	case time.Tuesday:
		return "tuesday"
	case time.Wednesday:
		return "wednesday"
	case time.Thursday:
		return "thursday"
	case time.Friday:
		return "friday"
	case time.Saturday:
		return "saturday"
	case time.Sunday:
		return "sunday"
	default:
		return "monday" // fallback
	}
}
