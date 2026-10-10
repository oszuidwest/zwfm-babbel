package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestStoryService_RejectsSilenceAndKeepsExistingAudio(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	inputPath := filepath.Join(t.TempDir(), "silent.wav")
	// #nosec G204 - local ffmpeg binary and controlled test fixture arguments
	cmd := exec.CommandContext(t.Context(), ffmpegPath,
		"-f", "lavfi", "-i", "anullsrc=r=48000:cl=mono:d=1", "-y", inputPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create silent audio: %v; output: %s", err, output)
	}
	// #nosec G304 - fixture generated inside t.TempDir
	silentAudio, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		run  func(ctx context.Context, s *StoryService, storyID int64) error
	}{
		{"upload", func(ctx context.Context, s *StoryService, storyID int64) error {
			target, err := s.PrepareAudio(ctx, storyID, nil)
			if err != nil {
				return err
			}
			return s.ProcessAudio(ctx, target, inputPath)
		}},
		{"forced TTS", func(ctx context.Context, s *StoryService, storyID int64) error {
			return s.GenerateTTS(ctx, storyID, nil, true)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, ProcessedPath: t.TempDir(),
			}}
			story := storyForTTSTest("News bulletin")
			story.AudioFile = "story_99.wav"
			finalPath := utils.StoryPath(cfg, story.AudioFile)
			existingAudio := []byte("existing audio must stay intact")
			if err := os.WriteFile(finalPath, existingAudio, 0600); err != nil {
				t.Fatal(err)
			}
			// The fake's nil repository makes any database update panic.
			service := newGenerateTTSTestService(story, &models.TTSSettings{}, nil, &fakeSpeechGenerator{data: silentAudio})
			service.config = cfg
			service.audioSvc = audio.NewService(cfg, nil)

			if err := tt.run(t.Context(), service, story.ID); !errors.Is(err, audio.ErrSilent) {
				t.Fatalf("error = %v, want audio.ErrSilent", err)
			}
			entries, err := os.ReadDir(cfg.Audio.ProcessedPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("processed files = %v, want only the existing audio", entries)
			}
			// #nosec G304 - canonical story path inside t.TempDir
			if got, err := os.ReadFile(finalPath); err != nil || !bytes.Equal(got, existingAudio) {
				t.Fatalf("existing audio = %q, %v; want %q", got, err, existingAudio)
			}
		})
	}
}

func TestStoryService_ProcessAudioPreservesUncertainPublication(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	inputPath := filepath.Join(t.TempDir(), "input.wav")
	// #nosec G204 - local ffmpeg binary and controlled test fixture arguments
	cmd := exec.CommandContext(t.Context(), ffmpegPath,
		"-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-y", inputPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create audio: %v; output: %s", err, output)
	}
	for _, tt := range []struct {
		name      string
		err       error
		committed bool
		wantFiles int
	}{
		{name: "response lost after commit", err: errors.New("connection lost"), committed: true, wantFiles: 2},
		{name: "connection lost before commit", err: errors.New("connection lost"), wantFiles: 2},
		{name: "concurrent change", err: repository.ErrStateConflict, wantFiles: 1},
		{name: "deleted during conversion", err: &repository.StoryDeletedError{ID: 99}, wantFiles: 1},
		{name: "missing during conversion", err: repository.ErrNotFound, wantFiles: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Audio: config.AudioConfig{
				FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
			}}
			story := storyForTTSTest("News")
			story.AudioFile = "story_99.wav"
			oldPath := utils.StoryPath(cfg, story.AudioFile)
			if err := os.WriteFile(oldPath, []byte("old audio"), 0600); err != nil {
				t.Fatal(err)
			}
			repo := &uncertainAudioRepository{err: tt.err, committed: tt.committed}
			svc := &StoryService{storyRepo: repo, audioSvc: audio.NewService(cfg, nil), config: cfg}
			err := svc.ProcessAudio(t.Context(), &AudioTarget{story: story, voice: story.Voice}, inputPath)
			if errors.Is(tt.err, repository.ErrNotFound) {
				if _, ok := errors.AsType[*apperrors.NotFoundError](err); !ok {
					t.Fatalf("ProcessAudio error = %v, want NotFoundError", err)
				}
			} else if !errors.Is(err, tt.err) {
				t.Fatalf("ProcessAudio error = %v, want %v", err, tt.err)
			}
			entries, err := os.ReadDir(cfg.Audio.ProcessedPath)
			if err != nil || len(entries) != tt.wantFiles {
				t.Fatalf("files = %v, error = %v, want %d files", entries, err, tt.wantFiles)
			}
			if _, err := os.Stat(oldPath); err != nil {
				t.Fatalf("previous audio removed: %v", err)
			}
			if repo.published != "" {
				if _, err := os.Stat(utils.StoryPath(cfg, repo.published)); err != nil {
					t.Fatalf("database references missing audio: %v", err)
				}
			}
		})
	}
}

type uncertainAudioRepository struct {
	storyRepository
	err       error
	committed bool
	published string
}

func (r *uncertainAudioRepository) UpdateAudio(_ context.Context, _ int64, update repository.StoryAudioUpdate) error {
	if r.committed {
		r.published = update.AudioFile
	}
	return r.err
}
