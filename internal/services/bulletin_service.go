package services

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
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

// BulletinServiceDeps contains bulletin generation dependencies.
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

	// stationLocks serializes generation per station between the job worker
	// and the synchronous automation path.
	stationLocks   map[int64]chan struct{}
	stationLocksMu sync.Mutex
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
		alerts:       notify.OrDiscard(deps.Alerts),
		stationLocks: make(map[int64]chan struct{}),
	}
}

// LockStation serializes bulletin generation for one station. It blocks until
// the lock is free or ctx ends; the returned function releases the lock.
// Callers start their generation timeout after acquisition so time spent
// waiting behind another generation does not consume it.
func (s *BulletinService) LockStation(ctx context.Context, stationID int64) (func(), error) {
	s.stationLocksMu.Lock()
	lock, ok := s.stationLocks[stationID]
	if !ok {
		lock = make(chan struct{}, 1)
		s.stationLocks[stationID] = lock
	}
	s.stationLocksMu.Unlock()

	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Create selects today's eligible stories, renders the WAV file, and persists
// the bulletin plus story links for a station. Callers must hold the station
// lock (LockStation).
func (s *BulletinService) Create(ctx context.Context, stationID int64) (*models.Bulletin, error) {
	bulletinID, err := s.create(ctx, stationID, nil)
	if err != nil {
		return nil, err
	}
	return s.GetByID(ctx, bulletinID)
}

// create renders and stores a bulletin; finalize joins the persistence
// transaction. Callers must hold the station lock (LockStation) so story
// selection and fair-rotation updates never interleave per station.
func (s *BulletinService) create(
	ctx context.Context,
	stationID int64,
	finalize func(context.Context, int64) error,
) (int64, error) {
	station, err := s.stationRepo.GetByID(ctx, stationID)
	if err != nil {
		return 0, apperrors.TranslateRepoError("Station", apperrors.OpQuery, err)
	}

	stories, err := s.selectStories(ctx, stationID, station.MaxStoriesPerBlock)
	if err != nil {
		return 0, err
	}

	noStoriesKey := fmt.Sprintf("bulletin:no-stories:station:%d", stationID)
	if len(stories) == 0 {
		s.alerts.Alert(ctx, notify.Event{
			Key:     noStoriesKey,
			Summary: fmt.Sprintf("No stories available for station %d", stationID),
			Details: "No eligible stories are available, so no on-air bulletin can be generated for this station.",
		})
		return 0, apperrors.NoStories(stationID)
	}
	s.alerts.Resolve(ctx, noStoriesKey,
		fmt.Sprintf("Stories available again for station %d", stationID), "Bulletin generation can continue.")

	s.reportVoiceConsistency(ctx, stationID, stories)

	jingle := prepareStoriesForPlayback(stories, rand.Shuffle)

	generationKey := fmt.Sprintf("bulletin:generation:station:%d", stationID)
	bulletinPath, err := s.generateBulletinAudio(ctx, station, stories, jingle)
	if err != nil {
		s.alerts.Alert(ctx, notify.Event{
			Key:               generationKey,
			Summary:           fmt.Sprintf("Bulletin generation failed for station %d", stationID),
			Details:           err.Error(),
			RequiresThreshold: errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		})
		return 0, err
	}
	s.alerts.Resolve(ctx, generationKey,
		fmt.Sprintf("Bulletin generation recovered for station %d", stationID), "Audio generation succeeded again.")

	var fileSize int64
	if fi, err := os.Stat(bulletinPath); err == nil {
		fileSize = fi.Size()
	}
	totalDuration := s.calculateBulletinDuration(station, stories, jingle.MixPoint)

	return s.saveBulletinToDatabase(ctx, saveBulletinParams{
		StationID:    stationID,
		BulletinPath: bulletinPath,
		Duration:     totalDuration,
		FileSize:     fileSize,
		Stories:      stories,
	}, finalize)
}

// prepareStoriesForPlayback captures jingle settings from the highest-priority
// story before randomizing the on-air order. Breaking priority and fair
// rotation determine which stories are selected; shuffling gives breaking
// stories varied positions during playback.
func prepareStoriesForPlayback(stories []repository.BulletinStoryData, shuffle func(int, func(int, int))) audio.JingleContext {
	jingle := audio.JingleContext{
		VoiceID:  stories[0].VoiceID,
		MixPoint: stories[0].MixPoint,
	}
	shuffle(len(stories), func(i, j int) {
		stories[i], stories[j] = stories[j], stories[i]
	})
	return jingle
}

// generateBulletinAudio renders to a temporary file and publishes the completed
// WAV by renaming it, so readers cannot open a partially rendered bulletin.
func (s *BulletinService) generateBulletinAudio(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle audio.JingleContext,
) (string, error) {
	timestamp := time.Now()
	bulletinPath := utils.GenerateBulletinPaths(s.config, station.ID, timestamp)
	temporaryPath := bulletinPath + ".tmp.wav"
	defer func() {
		if err := os.Remove(temporaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			logger.Warn("Failed to remove temporary bulletin audio", "path", temporaryPath, "error", err)
		}
	}()

	if err := s.audioSvc.CreateBulletin(ctx, station, stories, jingle, temporaryPath); err != nil {
		return "", apperrors.Audio("Bulletin", "generate", err)
	}
	if err := os.Rename(temporaryPath, bulletinPath); err != nil {
		return "", apperrors.Audio("Bulletin", "publish", err)
	}

	return bulletinPath, nil
}

// calculateBulletinDuration mirrors FFmpeg timing.
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

	if mixPoint > 0 {
		return storiesDuration + mixPoint
	}

	return storiesDuration
}

type saveBulletinParams struct {
	StationID    int64
	BulletinPath string
	Duration     float64
	FileSize     int64
	Stories      []repository.BulletinStoryData
}

// saveBulletinToDatabase stores the bulletin and story links atomically.
func (s *BulletinService) saveBulletinToDatabase(
	ctx context.Context,
	params saveBulletinParams,
	finalize func(context.Context, int64) error,
) (int64, error) {
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
		if finalize != nil {
			if err := finalize(txCtx, bulletinID); err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return 0, apperrors.TranslateRepoError("Bulletin", apperrors.OpCreate, err)
	}

	return bulletinID, nil
}

// GetLatest loads the most recent unpurged bulletin for a station.
// When maxAge is non-nil, only bulletins from the current local day within
// that age are returned.
func (s *BulletinService) GetLatest(
	ctx context.Context, stationID int64, maxAge *time.Duration,
) (*models.Bulletin, error) {
	bulletin, err := s.bulletinRepo.GetLatest(ctx, stationID, maxAge)
	if err != nil {
		return nil, apperrors.TranslateRepoError("Bulletin", apperrors.OpQuery, err)
	}

	return bulletin, nil
}

// selectStories loads today's eligible stories for a bulletin.
// Stories must be active, have audio, match the station's voice configuration,
// and be scheduled for the weekday.
// Breaking news stories are prioritized for selection; remaining slots use fair rotation.
func (s *BulletinService) selectStories(
	ctx context.Context, stationID int64, limit int,
) ([]repository.BulletinStoryData, error) {
	stories, err := s.storyRepo.GetStoriesForBulletin(ctx, stationID, time.Now(), limit)
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
		key := fmt.Sprintf("bulletin:missing-story-audio:station:%d:story:%d", stationID, story.ID)
		if _, err := os.Stat(path); err != nil {
			logger.Warn("Skipping story with missing audio file during bulletin generation",
				"story_id", story.ID, "station_id", stationID, "path", path, "error", err)
			s.alerts.Alert(ctx, notify.Event{
				Key:     key,
				Summary: fmt.Sprintf("Story audio missing for station %d", stationID),
				Details: fmt.Sprintf("Story %d exists in the database but its processed audio file is unavailable at %s: %v", story.ID, path, err),
			})
			continue
		}
		s.alerts.Resolve(ctx, key,
			fmt.Sprintf("Story audio recovered for station %d", stationID),
			fmt.Sprintf("Processed audio for story %d is readable again.", story.ID))
		kept = append(kept, story)
	}
	return kept
}

// reportVoiceConsistency maintains one multi-voice alert per station.
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
		s.alerts.Resolve(ctx, key, fmt.Sprintf("Bulletin voices aligned for station %d", stationID),
			"All selected stories use the same voice again.")
		return
	}

	logger.Debug("Bulletin uses stories with different voices", "station_id", stationID, "voice_ids", voiceIDs)
	s.alerts.Alert(ctx, notify.Event{
		Key:     key,
		Summary: fmt.Sprintf("Multiple voices selected for station %d", stationID),
		Details: fmt.Sprintf("Selected stories use voice IDs %v; the bulletin jingle is based on the first story.", voiceIDs),
	})
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
