// Package services provides domain services for the Babbel API.
package services

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// BulletinServiceDeps contains all dependencies for BulletinService.
type BulletinServiceDeps struct {
	TxManager    repository.TxManager
	BulletinRepo repository.BulletinRepository
	StationRepo  repository.StationRepository
	StoryRepo    repository.StoryRepository
	AudioSvc     *audio.Service
	Config       *config.Config
}

// BulletinService handles bulletin generation and retrieval operations.
type BulletinService struct {
	txManager    repository.TxManager
	bulletinRepo repository.BulletinRepository
	stationRepo  repository.StationRepository
	storyRepo    repository.StoryRepository
	audioSvc     *audio.Service
	config       *config.Config
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
	}
}

// Create generates a new bulletin for the specified station and date.
// Returns the created bulletin with all computed fields populated.
func (s *BulletinService) Create(ctx context.Context, stationID int64, targetDate time.Time) (*models.Bulletin, error) {
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
		return nil, apperrors.NoStories(stationID)
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

	// Fetch the created bulletin with Station preloaded for computed fields
	return s.GetByID(ctx, bulletinID)
}

// validateAndFetchStation validates that a station exists and returns its details.
func (s *BulletinService) validateAndFetchStation(ctx context.Context, stationID int64) (*models.Station, error) {
	station, err := s.stationRepo.GetByID(ctx, stationID)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}
	return station, nil
}

// generateBulletinAudio creates the audio file for a bulletin and returns its path.
func (s *BulletinService) generateBulletinAudio(ctx context.Context, station *models.Station, stories []repository.BulletinStoryData) (string, error) {
	// Generate consistent paths using single timestamp
	timestamp := time.Now()
	bulletinPath, _ := utils.GenerateBulletinPaths(s.config, station.ID, timestamp)

	// Create bulletin using the generated absolute path
	createdPath, err := s.audioSvc.CreateBulletin(ctx, station, stories, bulletinPath)
	if err != nil {
		return "", apperrors.Audio("Bulletin", "generate", err)
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
func (s *BulletinService) calculateBulletinDuration(station *models.Station, stories []repository.BulletinStoryData) float64 {
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
	if len(stories) > 0 && stories[0].MixPoint > 0 {
		mixPointDelay = stories[0].MixPoint
	}

	// Total duration = stories duration + pauses + mix point delay
	return storiesDuration + mixPointDelay
}

// saveBulletinToDatabase persists the bulletin record and story relationships in a transaction.
func (s *BulletinService) saveBulletinToDatabase(ctx context.Context, stationID int64, bulletinPath string, duration float64, fileSize int64, stories []repository.BulletinStoryData) (int64, error) {
	var bulletinID int64

	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// Insert bulletin record
		filename := filepath.Base(bulletinPath)
		id, err := s.bulletinRepo.Create(txCtx, stationID, filename, filename, duration, fileSize, len(stories))
		if err != nil {
			return err
		}
		bulletinID = id

		// Link stories to bulletin
		storyIDs := make([]int64, len(stories))
		for i, story := range stories {
			storyIDs[i] = story.ID
		}

		if err := s.bulletinRepo.LinkStories(txCtx, bulletinID, storyIDs); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return 0, apperrors.Database("Bulletin", "create", err)
	}

	return bulletinID, nil
}

// GetLatest retrieves the most recent bulletin for a station.
// If maxAge is provided, only returns bulletins newer than that duration.
func (s *BulletinService) GetLatest(ctx context.Context, stationID int64, maxAge *time.Duration) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetLatest(ctx, stationID, maxAge)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}

	return bulletin, nil
}

// GetStoriesForDate retrieves eligible stories for bulletin generation on a specific date.
// Stories must be active, have audio, match the station's voice configuration, and be scheduled for the weekday.
// Uses fair rotation to ensure all stories get equal airtime throughout the day.
func (s *BulletinService) GetStoriesForDate(ctx context.Context, stationID int64, date time.Time, limit int) ([]repository.BulletinStoryData, error) {
	stories, err := s.storyRepo.GetStoriesForBulletin(ctx, stationID, date, limit)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
	}

	// Debug logging for story selection (fair rotation transparency)
	if len(stories) > 0 {
		storyIDs := make([]int64, len(stories))
		for i, story := range stories {
			storyIDs[i] = story.ID
		}
		logger.Debug("Fair rotation selected %d stories for station %d: IDs=%v", len(stories), stationID, storyIDs)
	}

	return stories, nil
}

// ParseTargetDate parses a date string in YYYY-MM-DD format or returns the current date if empty.
// Uses local timezone to ensure consistent date handling across the application.
func ParseTargetDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Now(), nil
	}
	parsedDate, err := time.ParseInLocation("2006-01-02", dateStr, time.Local)
	if err != nil {
		return time.Time{}, apperrors.Validation("Bulletin", "date", "invalid date format (expected YYYY-MM-DD)")
	}
	return parsedDate, nil
}

// List retrieves bulletins with pagination, filtering, and sorting.
func (s *BulletinService) List(ctx context.Context, query *repository.ListQuery) (*repository.ListResult[models.Bulletin], error) {
	result, err := s.bulletinRepo.List(ctx, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return result, nil
}

// Exists reports whether a bulletin with the given ID exists.
func (s *BulletinService) Exists(ctx context.Context, id int64) (bool, error) {
	exists, err := s.bulletinRepo.Exists(ctx, id)
	if err != nil {
		return false, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return exists, nil
}

// GetByID retrieves a bulletin by its ID.
func (s *BulletinService) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return bulletin, nil
}

// GetBulletinStories retrieves stories included in a specific bulletin with pagination.
func (s *BulletinService) GetBulletinStories(ctx context.Context, bulletinID int64, limit, offset int) ([]models.BulletinStory, int64, error) {
	stories, total, err := s.bulletinRepo.GetBulletinStories(ctx, bulletinID, limit, offset)
	if err != nil {
		return nil, 0, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return stories, total, nil
}

// GetStationBulletins retrieves bulletins for a specific station with pagination.
func (s *BulletinService) GetStationBulletins(ctx context.Context, stationID int64, query *repository.ListQuery) (*repository.ListResult[models.Bulletin], error) {
	result, err := s.bulletinRepo.GetStationBulletins(ctx, stationID, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return result, nil
}

// GetStoryBulletinHistory retrieves bulletins that included a specific story.
func (s *BulletinService) GetStoryBulletinHistory(ctx context.Context, storyID int64, query *repository.ListQuery) (*repository.ListResult[models.Bulletin], error) {
	result, err := s.bulletinRepo.GetStoryBulletinHistory(ctx, storyID, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return result, nil
}
