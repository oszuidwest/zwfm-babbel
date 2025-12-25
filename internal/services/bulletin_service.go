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
	// Get station
	var station models.Station
	err := s.db.Get(&station, "SELECT * FROM stations WHERE id = ?", stationID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%w: station not found", ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to fetch station: %v", ErrDatabaseError, err)
	}

	// Get stories for the date
	stories, err := s.GetStoriesForDate(ctx, stationID, targetDate, station.MaxStoriesPerBlock)
	if err != nil {
		return nil, err
	}

	if len(stories) == 0 {
		return nil, ErrNoStoriesAvailable
	}

	// Generate consistent paths using single timestamp
	timestamp := time.Now()
	bulletinPath, _ := utils.GenerateBulletinPaths(s.config, stationID, timestamp)

	// Create bulletin using the generated absolute path
	createdPath, err := s.audioSvc.CreateBulletin(ctx, &station, stories, bulletinPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAudioProcessingFailed, err)
	}

	// Verify the paths match (should always be true with unified function)
	if createdPath != bulletinPath {
		// This should never happen with the unified function, but log if it does
		log.Printf("WARNING: Path mismatch - created: %s, expected: %s", createdPath, bulletinPath)
	}

	// Get file info (bulletinPath is the full absolute path)
	fileInfo, err := os.Stat(bulletinPath)
	var fileSize int64
	if err == nil {
		fileSize = fileInfo.Size()
	}

	// Calculate total duration including mix point and pauses
	var totalDuration float64

	// Calculate total duration of all stories + pauses
	var storiesDuration float64
	for _, story := range stories {
		if story.DurationSeconds != nil {
			storiesDuration += *story.DurationSeconds
		}
	}
	if station.PauseSeconds > 0 && len(stories) > 1 {
		storiesDuration += station.PauseSeconds * float64(len(stories)-1)
	}

	// Add mix point delay (when voice starts over jingle)
	var mixPointDelay float64
	if len(stories) > 0 && stories[0].VoiceMixPoint > 0 {
		mixPointDelay = stories[0].VoiceMixPoint
	}

	// Total duration = stories duration + pauses + mix point delay
	// The bulletin ends when all stories finish playing (jingle plays underneath)
	totalDuration = storiesDuration + mixPointDelay

	// Save bulletin record to database using the consistent relative path
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO bulletins (station_id, filename, audio_file, duration_seconds, file_size, story_count)
		VALUES (?, ?, ?, ?, ?, ?)`,
		stationID,
		filepath.Base(bulletinPath),
		filepath.Base(bulletinPath),
		totalDuration,
		fileSize,
		len(stories),
	)

	var bulletinID int64
	if err == nil {
		var idErr error
		bulletinID, idErr = result.LastInsertId()
		if idErr != nil {
			log.Printf("WARNING: Failed to get bulletin ID: %v", idErr)
		}

		// Insert bulletin-story relationships with order
		if bulletinID > 0 {
			for i, story := range stories {
				_, err = s.db.ExecContext(ctx,
					"INSERT INTO bulletin_stories (bulletin_id, story_id, story_order) VALUES (?, ?, ?)",
					bulletinID, story.ID, i,
				)
				if err != nil {
					logger.Error("Failed to insert bulletin story: %v", err)
				}
			}
		}
	} else {
		return nil, fmt.Errorf("%w: failed to save bulletin: %v", ErrDatabaseError, err)
	}

	return &BulletinInfo{
		ID:           bulletinID,
		Station:      station,
		Stories:      stories,
		BulletinPath: bulletinPath,
		Duration:     totalDuration,
		FileSize:     fileSize,
		CreatedAt:    time.Now(),
	}, nil
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
