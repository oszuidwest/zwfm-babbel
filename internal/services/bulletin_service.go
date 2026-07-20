package services

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// BulletinServiceDeps groups the collaborators required for selecting,
// rendering, and persisting bulletins.
type BulletinServiceDeps struct {
	TxManager    repository.TxManager
	BulletinRepo *repository.BulletinRepository
	StationRepo  *repository.StationRepository
	StoryRepo    *repository.StoryRepository
	AudioSvc     *audio.Service
	Config       *config.Config
	Alerts       notify.Alerter
}

// BulletinService generates audio bulletins and exposes bulletin read models.
type BulletinService struct {
	txManager    repository.TxManager
	bulletinRepo *repository.BulletinRepository
	stationRepo  *repository.StationRepository
	storyRepo    *repository.StoryRepository
	audioSvc     *audio.Service
	config       *config.Config
	alerts       notify.Alerter
}

// NewBulletinService returns a bulletin service wired to deps.
func NewBulletinService(deps BulletinServiceDeps) *BulletinService {
	return &BulletinService{
		txManager:    deps.TxManager,
		bulletinRepo: deps.BulletinRepo,
		stationRepo:  deps.StationRepo,
		storyRepo:    deps.StoryRepo,
		audioSvc:     deps.AudioSvc,
		config:       deps.Config,
		alerts:       deps.Alerts,
	}
}

// Create selects eligible stories, renders the WAV file, and persists the
// bulletin plus story links for a station/date.
func (s *BulletinService) Create(ctx context.Context, stationID int64, targetDate time.Time) (*models.Bulletin, error) {
	station, err := s.stationRepo.GetByID(ctx, stationID)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}

	stories, err := s.GetStoriesForDate(ctx, stationID, targetDate, station.MaxStoriesPerBlock)
	if err != nil {
		return nil, err
	}

	if len(stories) == 0 {
		s.alert(ctx, notify.Event{
			Key:     fmt.Sprintf("bulletin:no-stories:station:%d", stationID),
			Summary: fmt.Sprintf("No stories available for station %d", stationID),
			Details: "The public automation endpoint cannot generate an on-air bulletin for this station.",
			Kind:    notify.KindImmediate,
		})
		return nil, apperrors.NoStories(stationID)
	}
	s.resolve(ctx, fmt.Sprintf("bulletin:no-stories:station:%d", stationID),
		fmt.Sprintf("Stories available again for station %d", stationID), "Bulletin generation can continue.")

	// Capture jingle context from the highest-priority story (first in SQL order)
	// before shuffling - jingle selection must be stable regardless of playback order.
	jingle := audio.JingleContext{
		VoiceID:  stories[0].VoiceID,
		MixPoint: stories[0].MixPoint,
	}
	s.reportVoiceConsistency(ctx, stationID, stories)

	// Shuffle story order for natural radio flow.
	// Breaking priority and fair rotation determine which stories are selected;
	// playback order is randomized so breaking stories appear in varied positions.
	rand.Shuffle(len(stories), func(i, j int) {
		stories[i], stories[j] = stories[j], stories[i]
	})

	bulletinPath, err := s.generateBulletinAudio(ctx, station, stories, jingle)
	if err != nil {
		kind := notify.KindImmediate
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			kind = notify.KindContinuous
		}
		s.alert(ctx, notify.Event{
			Key:     fmt.Sprintf("bulletin:generation:station:%d", stationID),
			Summary: fmt.Sprintf("Bulletin generation failed for station %d", stationID),
			Details: err.Error(),
			Kind:    kind,
		})
		return nil, err
	}
	s.resolve(ctx, fmt.Sprintf("bulletin:generation:station:%d", stationID),
		fmt.Sprintf("Bulletin generation recovered for station %d", stationID), "Audio generation succeeded again.")

	var fileSize int64
	if fi, err := os.Stat(bulletinPath); err == nil {
		fileSize = fi.Size()
	}
	totalDuration := s.calculateBulletinDuration(station, stories, jingle.MixPoint)

	bulletinID, err := s.saveBulletinToDatabase(ctx, saveBulletinParams{
		StationID:    stationID,
		BulletinPath: bulletinPath,
		Duration:     totalDuration,
		FileSize:     fileSize,
		Stories:      stories,
	})
	if err != nil {
		return nil, err
	}

	return s.GetByID(ctx, bulletinID)
}

// generateBulletinAudio renders a bulletin with one timestamp shared by the
// filesystem path and database filename.
func (s *BulletinService) generateBulletinAudio(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle audio.JingleContext,
) (string, error) {
	timestamp := time.Now()
	bulletinPath := utils.GenerateBulletinPaths(s.config, station.ID, timestamp)

	if _, err := s.audioSvc.CreateBulletin(ctx, station, stories, jingle, bulletinPath); err != nil {
		return "", apperrors.Audio("Bulletin", "generate", err)
	}

	return bulletinPath, nil
}

// calculateBulletinDuration computes the total duration including stories, pauses, and mix points.
func (s *BulletinService) calculateBulletinDuration(
	station *models.Station, stories []repository.BulletinStoryData, mixPoint float64,
) float64 {
	var storiesDuration float64
	for _, story := range stories {
		if story.DurationSeconds != nil {
			storiesDuration += *story.DurationSeconds
		}
	}

	if station.PauseSeconds > 0 && len(stories) > 1 {
		storiesDuration += station.PauseSeconds * float64(len(stories)-1)
	}

	// Keep stored duration aligned with the FFmpeg path, which only delays for positive mix points.
	if mixPoint > 0 {
		return storiesDuration + mixPoint
	}

	return storiesDuration
}

// saveBulletinParams groups the values stored when a generated bulletin is
// committed.
type saveBulletinParams struct {
	StationID    int64
	BulletinPath string
	Duration     float64
	FileSize     int64
	Stories      []repository.BulletinStoryData
}

// saveBulletinToDatabase stores the bulletin and its story links in one
// transaction.
func (s *BulletinService) saveBulletinToDatabase(ctx context.Context, params saveBulletinParams) (int64, error) {
	var bulletinID int64

	err := s.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		filename := filepath.Base(params.BulletinPath)
		id, err := s.bulletinRepo.Create(txCtx, repository.CreateBulletinParams{
			StationID:  params.StationID,
			Filename:   filename,
			AudioFile:  filename,
			Duration:   params.Duration,
			FileSize:   params.FileSize,
			StoryCount: len(params.Stories),
		})
		if err != nil {
			return err
		}
		bulletinID = id

		storyIDs := make([]int64, len(params.Stories))
		for i, story := range params.Stories {
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

// GetLatest loads the most recent bulletin for a station.
// When maxAge is non-nil, older bulletins are treated as not found.
func (s *BulletinService) GetLatest(
	ctx context.Context, stationID int64, maxAge *time.Duration,
) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetLatest(ctx, stationID, maxAge)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}

	return bulletin, nil
}

// GetStoriesForDate loads stories eligible for bulletin generation on date.
// Stories must be active, have audio, match the station's voice configuration,
// and be scheduled for the weekday.
// Breaking news stories are prioritized for selection; remaining slots use fair rotation.
func (s *BulletinService) GetStoriesForDate(
	ctx context.Context, stationID int64, date time.Time, limit int,
) ([]repository.BulletinStoryData, error) {
	stories, err := s.storyRepo.GetStoriesForBulletin(ctx, stationID, date, limit)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Story", apperrors.OpQuery, err)
	}

	// The eligibility query only checks the DB audio_file column; the physical file can still be
	// absent (manual deletion, failed processing, storage issue). Including such a story would make
	// FFmpeg fail the entire bulletin with a 500, so drop it here. If none remain, Create returns
	// NoStories (422) instead of leaking an internal error.
	stories = s.filterStoriesWithMissingAudio(ctx, stories, stationID)

	if len(stories) > 0 && len(stories) == limit {
		breakingCount := 0
		for _, story := range stories {
			if story.IsBreaking {
				breakingCount++
			}
		}
		if breakingCount == len(stories) {
			logger.Warn("All bulletin slots consumed by breaking stories; non-breaking stories excluded",
				"slot_count", len(stories), "station_id", stationID)
		}
	}

	if len(stories) > 0 {
		storyIDs := make([]int64, len(stories))
		for i, story := range stories {
			storyIDs[i] = story.ID
		}
		logger.Debug("Story selection complete", "story_count", len(stories), "station_id", stationID, "story_ids", storyIDs)
	}

	return stories, nil
}

// filterStoriesWithMissingAudio drops stories whose processed audio file is absent on disk.
// Generation reads each story file directly via FFmpeg, so a missing file would abort the whole
// bulletin; skipping the story keeps generation resilient to storage inconsistencies.
func (s *BulletinService) filterStoriesWithMissingAudio(
	ctx context.Context, stories []repository.BulletinStoryData, stationID int64,
) []repository.BulletinStoryData {
	kept := make([]repository.BulletinStoryData, 0, len(stories))
	for _, story := range stories {
		path := utils.StoryPath(s.config, story.ID)
		if _, err := os.Stat(path); err != nil {
			logger.Warn("Skipping story with missing audio file during bulletin generation",
				"story_id", story.ID, "station_id", stationID, "path", path, "error", err)
			s.alert(ctx, notify.Event{
				Key:     fmt.Sprintf("bulletin:missing-story-audio:station:%d:story:%d", stationID, story.ID),
				Summary: fmt.Sprintf("Story audio missing for station %d", stationID),
				Details: fmt.Sprintf("Story %d exists in the database but its processed audio file is unavailable at %s: %v", story.ID, path, err),
				Kind:    notify.KindImmediate,
			})
			continue
		}
		s.resolve(ctx, fmt.Sprintf("bulletin:missing-story-audio:station:%d:story:%d", stationID, story.ID),
			fmt.Sprintf("Story audio recovered for station %d", stationID),
			fmt.Sprintf("Processed audio for story %d is readable again.", story.ID))
		kept = append(kept, story)
	}
	return kept
}

func (s *BulletinService) reportVoiceConsistency(
	ctx context.Context, stationID int64, stories []repository.BulletinStoryData,
) {
	key := fmt.Sprintf("bulletin:multiple-voices:station:%d", stationID)
	seen := make(map[int64]struct{})
	voiceIDs := make([]int64, 0)
	for _, story := range stories {
		if story.VoiceID == nil {
			continue
		}
		if _, exists := seen[*story.VoiceID]; exists {
			continue
		}
		seen[*story.VoiceID] = struct{}{}
		voiceIDs = append(voiceIDs, *story.VoiceID)
	}

	if len(voiceIDs) <= 1 {
		s.resolve(ctx, key, fmt.Sprintf("Bulletin voices aligned for station %d", stationID),
			"All selected stories use the same voice again.")
		return
	}

	logger.Debug("Bulletin uses stories with different voices", "station_id", stationID, "voice_ids", voiceIDs)
	s.alert(ctx, notify.Event{
		Key:     key,
		Summary: fmt.Sprintf("Multiple voices selected for station %d", stationID),
		Details: fmt.Sprintf("Selected stories use voice IDs %v; the bulletin jingle is based on the first story.", voiceIDs),
		Kind:    notify.KindImmediate,
	})
}

func (s *BulletinService) alert(ctx context.Context, event notify.Event) {
	if s.alerts != nil {
		s.alerts.Alert(ctx, event)
	}
}

func (s *BulletinService) resolve(ctx context.Context, key, summary, details string) {
	if s.alerts != nil {
		s.alerts.Resolve(ctx, key, summary, details)
	}
}

// ParseTargetDate parses YYYY-MM-DD in the local timezone.
// Empty input returns the current instant so callers can generate "today".
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
func (s *BulletinService) List(
	ctx context.Context, query *repository.ListQuery,
) (*repository.ListResult[models.Bulletin], error) {
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

// GetByID loads a bulletin by ID and translates repository errors.
func (s *BulletinService) GetByID(ctx context.Context, id int64) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetByID(ctx, id)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return bulletin, nil
}

// GetBulletinStories retrieves stories included in a specific bulletin with pagination.
func (s *BulletinService) GetBulletinStories(
	ctx context.Context, bulletinID int64, limit, offset int,
) ([]models.BulletinStory, int64, error) {
	stories, total, err := s.bulletinRepo.GetBulletinStories(ctx, bulletinID, limit, offset)
	if err != nil {
		return nil, 0, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return stories, total, nil
}

// GetStationBulletins retrieves bulletins for a specific station with pagination.
func (s *BulletinService) GetStationBulletins(
	ctx context.Context, stationID int64, query *repository.ListQuery,
) (*repository.ListResult[models.Bulletin], error) {
	result, err := s.bulletinRepo.GetStationBulletins(ctx, stationID, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return result, nil
}

// GetStoryBulletinHistory retrieves bulletins that included a specific story.
func (s *BulletinService) GetStoryBulletinHistory(
	ctx context.Context, storyID int64, query *repository.ListQuery,
) (*repository.ListResult[models.Bulletin], error) {
	result, err := s.bulletinRepo.GetStoryBulletinHistory(ctx, storyID, query)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}
	return result, nil
}
