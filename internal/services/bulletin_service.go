// Package services provides domain services for the Babbel API.
package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
	"gorm.io/gorm"
)

// BulletinServiceDeps contains all dependencies for BulletinService.
type BulletinServiceDeps struct {
	TxManager    repository.TxManager
	BulletinRepo repository.BulletinRepository
	StationRepo  repository.StationRepository
	StoryRepo    repository.StoryRepository
	AudioSvc     *audio.Service
	Config       *config.Config
	GormDB       *gorm.DB
}

// BulletinService handles bulletin generation and retrieval operations.
type BulletinService struct {
	txManager    repository.TxManager
	bulletinRepo repository.BulletinRepository
	stationRepo  repository.StationRepository
	storyRepo    repository.StoryRepository
	audioSvc     *audio.Service
	config       *config.Config
	gormDB       *gorm.DB
}

// NewBulletinService creates a new bulletin service instance.
func NewBulletinService(deps BulletinServiceDeps) *BulletinService {
	return &BulletinService{
		txManager:    deps.TxManager,
		bulletinRepo: deps.BulletinRepo,
		stationRepo:  deps.StationRepo,
		storyRepo:    deps.StoryRepo,
		audioSvc:     deps.AudioSvc,
		config:       deps.Config,
		gormDB:       deps.GormDB,
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
func (s *BulletinService) Create(ctx context.Context, stationID int64, targetDate time.Time) (*BulletinInfo, error) {
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
		return nil, apperrors.ErrNoStoriesAvailable
	}

	// Generate audio file
	bulletinPath, err := s.generateBulletinAudio(ctx, station, stories)
	if err != nil {
		return nil, err
	}

	// Get file metadata
	fileSize := s.getFileSize(bulletinPath)
	totalDuration := s.calculateBulletinDuration(station, stories)

	// Persist bulletin to database using transaction
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
func (s *BulletinService) validateAndFetchStation(ctx context.Context, stationID int64) (*models.Station, error) {
	station, err := s.stationRepo.GetByID(ctx, stationID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: station not found", apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to fetch station: %v", apperrors.ErrDatabaseError, err)
	}
	return station, nil
}

// generateBulletinAudio creates the audio file for a bulletin and returns its path.
func (s *BulletinService) generateBulletinAudio(ctx context.Context, station *models.Station, stories []models.Story) (string, error) {
	// Generate consistent paths using single timestamp
	timestamp := time.Now()
	bulletinPath, _ := utils.GenerateBulletinPaths(s.config, station.ID, timestamp)

	// Create bulletin using the generated absolute path
	createdPath, err := s.audioSvc.CreateBulletin(ctx, station, stories, bulletinPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", apperrors.ErrAudioProcessingFailed, err)
	}

	// Verify the paths match (should always be true with unified function)
	if createdPath != bulletinPath {
		logger.Warn("Path mismatch - created: %s, expected: %s", createdPath, bulletinPath)
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
func (s *BulletinService) saveBulletinToDatabase(ctx context.Context, stationID int64, bulletinPath string, duration float64, fileSize int64, stories []models.Story) (int64, error) {
	var bulletinID int64

	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Insert bulletin record
		filename := filepath.Base(bulletinPath)
		id, err := s.bulletinRepo.Create(txCtx, stationID, filename, filename, duration, fileSize, len(stories))
		if err != nil {
			return fmt.Errorf("failed to save bulletin: %v", err)
		}
		bulletinID = id

		// Link stories to bulletin
		storyIDs := make([]int64, len(stories))
		for i, story := range stories {
			storyIDs[i] = story.ID
		}

		if err := s.bulletinRepo.LinkStories(txCtx, bulletinID, storyIDs); err != nil {
			return fmt.Errorf("failed to link stories: %v", err)
		}

		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("%w: %v", apperrors.ErrDatabaseError, err)
	}

	return bulletinID, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (s *BulletinService) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetLatest(ctx, stationID, maxAge)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, fmt.Errorf("%w: no bulletin found for station", apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("%w: failed to fetch bulletin: %v", apperrors.ErrDatabaseError, err)
	}

	return bulletin, nil
}

// GetStoriesForDate retrieves eligible stories for bulletin generation on a specific date.
// Stories must be active, have audio, match the station's voice configuration, and be scheduled for the weekday.
func (s *BulletinService) GetStoriesForDate(ctx context.Context, stationID int64, date time.Time, limit int) ([]models.Story, error) {
	stories, err := s.storyRepo.GetStoriesForBulletin(ctx, stationID, date, limit)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch stories: %v", apperrors.ErrDatabaseError, err)
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
		return time.Time{}, fmt.Errorf("%w: invalid date format (expected YYYY-MM-DD)", apperrors.ErrInvalidInput)
	}
	return parsedDate, nil
}

// ListWithContext handles paginated list requests with query parameters.
// Encapsulates query configuration and writes JSON response directly.
func (s *BulletinService) ListWithContext(c *gin.Context) {
	config := utils.GormListConfig{
		SearchFields: []string{"filename"},
		FieldMapping: map[string]string{
			"id":               "id",
			"station_id":       "station_id",
			"filename":         "filename",
			"duration_seconds": "duration_seconds",
			"duration":         "duration_seconds",
			"file_size":        "file_size",
			"story_count":      "story_count",
			"created_at":       "created_at",
		},
		DefaultSort: "created_at DESC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.Bulletin](c, s.gormDB, config)
}

// GetStationBulletinsWithContext returns paginated bulletins for a specific station.
func (s *BulletinService) GetStationBulletinsWithContext(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	config := utils.GormListConfig{
		SearchFields: []string{},
		FieldMapping: map[string]string{
			"id":               "id",
			"station_id":       "station_id",
			"filename":         "filename",
			"duration_seconds": "duration_seconds",
			"duration":         "duration_seconds",
			"file_size":        "file_size",
			"story_count":      "story_count",
			"created_at":       "created_at",
		},
		DefaultSort: "created_at DESC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.Bulletin](c, s.gormDB.Where("station_id = ?", stationID), config)
}

// GetStoryBulletinHistoryWithContext returns paginated bulletins that included a specific story.
func (s *BulletinService) GetStoryBulletinHistoryWithContext(c *gin.Context) {
	storyID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	config := utils.GormListConfig{
		SearchFields: []string{},
		FieldMapping: map[string]string{
			"id":               "bulletins.id",
			"station_id":       "bulletins.station_id",
			"filename":         "bulletins.filename",
			"duration_seconds": "bulletins.duration_seconds",
			"duration":         "bulletins.duration_seconds",
			"file_size":        "bulletins.file_size",
			"story_count":      "bulletins.story_count",
			"created_at":       "bulletins.created_at",
			"story_order":      "bulletin_stories.story_order",
			"included_at":      "bulletin_stories.created_at",
		},
		DefaultSort: "bulletin_stories.created_at DESC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.StoryBulletinHistory](c,
		s.gormDB.Table("bulletins").
			Select("bulletins.*, bulletin_stories.story_order, bulletin_stories.created_at as included_at").
			Joins("JOIN bulletin_stories ON bulletins.id = bulletin_stories.bulletin_id").
			Where("bulletin_stories.story_id = ?", storyID),
		config)
}

// GetBulletinStoriesWithContext returns paginated stories for a specific bulletin.
func (s *BulletinService) GetBulletinStoriesWithContext(c *gin.Context) {
	bulletinID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	config := utils.GormListConfig{
		SearchFields: []string{"stories.title"},
		FieldMapping: map[string]string{
			"id":          "bulletin_stories.id",
			"bulletin_id": "bulletin_stories.bulletin_id",
			"story_id":    "bulletin_stories.story_id",
			"story_order": "bulletin_stories.story_order",
			"created_at":  "bulletin_stories.created_at",
			"story_title": "stories.title",
		},
		DefaultSort: "bulletin_stories.story_order ASC",
		SoftDelete:  false,
	}
	utils.GormListWithQuery[models.BulletinStory](c,
		s.gormDB.Table("bulletin_stories").
			Select("bulletin_stories.*, stories.title as story_title, stations.name as station_name, bulletins.filename as bulletin_filename, bulletins.station_id").
			Joins("JOIN stories ON bulletin_stories.story_id = stories.id").
			Joins("JOIN bulletins ON bulletin_stories.bulletin_id = bulletins.id").
			Joins("JOIN stations ON bulletins.station_id = stations.id").
			Where("bulletin_stories.bulletin_id = ?", bulletinID),
		config)
}

// GormDB returns the GORM database instance for validation helpers.
func (s *BulletinService) GormDB() *gorm.DB {
	return s.gormDB
}
