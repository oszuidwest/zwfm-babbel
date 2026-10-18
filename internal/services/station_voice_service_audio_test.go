package services

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

type jingleAudioRepository struct {
	stationVoiceRepository
	update    func()
	err       error
	id        int64
	audioFile string
}

func (r *jingleAudioRepository) UpdateAudio(ctx context.Context, id int64, filename string) error {
	if ctx.Value(jingleTxKey{}) == nil {
		return errors.New("UpdateAudio ran outside the transaction")
	}
	if r.update != nil {
		r.update()
	}
	if r.err != nil {
		return r.err
	}
	r.id, r.audioFile = id, filename
	return nil
}

type jingleTxKey struct{}

// jingleTxManager marks the transaction context and records rollbacks. A
// non-nil err fails the transaction: before fn when beginFails, otherwise at
// commit after fn succeeds.
type jingleTxManager struct {
	beginFails bool
	err        error
	rolledBack bool
}

func (m *jingleTxManager) WithTransaction(ctx context.Context, fn func(context.Context) error) error {
	if m.beginFails {
		return m.err
	}
	if err := fn(context.WithValue(ctx, jingleTxKey{}, true)); err != nil {
		m.rolledBack = true
		return err
	}
	if m.err != nil {
		return m.err
	}
	// database/sql rolls back a transaction whose context is cancelled.
	return ctx.Err()
}

func TestStationVoiceService_CancelledJingleKeepsExistingAudio(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not executable on windows")
	}
	service, stationVoice := newJingleTestService(t, nil)
	input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=30")
	existing := seedJingle(t, service, stationVoice)

	// Real-time input keeps real FFmpeg running until we observe output and
	// cancel it. exec lets CommandContext kill FFmpeg rather than a parent shell.
	script := "#!/bin/sh\nexec '" + strings.ReplaceAll(service.config.Audio.FFmpegPath, "'", "'\\''") + "' -re \"$@\"\n"
	ffmpegPath := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(ffmpegPath, []byte(script), 0o700); err != nil { //nolint:gosec // Test executable invoking real FFmpeg.
		t.Fatal(err)
	}
	service.config.Audio.FFmpegPath = ffmpegPath
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		done <- service.ProcessJingle(ctx, stationVoice, input)
		close(stopped)
	}()
	defer func() { cancel(); <-stopped }()

	// More bytes than the old jingle proves FFmpeg has written output. The
	// live path is watched too, so conversion straight onto it also fails.
	livePath := utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID)
	written := func() bool {
		converted, _ := filepath.Glob(filepath.Join(service.config.Audio.ProcessedPath, "*.processing", "*"))
		for _, path := range append(converted, livePath) {
			if info, err := os.Stat(path); err == nil && info.Size() > int64(len(existing)) {
				return true
			}
		}
		return false
	}
	for !written() {
		select {
		case err := <-done:
			t.Fatalf("conversion finished before cancellation: %v", err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for FFmpeg to write output")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessJingle() = %v, want context.Canceled", err)
	}
	assertJingleContent(t, service, stationVoice, existing)
	assertNoProcessingJingles(t, service, stationVoice)
}

func TestStationVoiceService_JingleDatabaseFailureKeepsExistingAudio(t *testing.T) {
	t.Parallel()
	databaseDown := errors.New("database down")
	repo := &jingleAudioRepository{err: databaseDown}
	service, stationVoice := newJingleTestService(t, repo)
	input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=1")
	existing := seedJingle(t, service, stationVoice)

	err := service.ProcessJingle(t.Context(), stationVoice, input)
	if _, ok := errors.AsType[*apperrors.DatabaseError](err); !ok || !errors.Is(err, databaseDown) {
		t.Fatalf("ProcessJingle() = %v, want the database error", err)
	}
	assertJingleContent(t, service, stationVoice, existing)
	assertNoProcessingJingles(t, service, stationVoice)
}

func TestStationVoiceService_JingleTransactionFailuresAreDatabaseErrors(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name       string
		beginFails bool
	}{
		{name: "begin", beginFails: true},
		{name: "commit"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			service, stationVoice := newJingleTestService(t, &jingleAudioRepository{})
			cause := errors.New("connection refused")
			service.txManager = &jingleTxManager{beginFails: tt.beginFails, err: cause}
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=1")
			existing := seedJingle(t, service, stationVoice)

			err := service.ProcessJingle(t.Context(), stationVoice, input)
			dbErr, ok := errors.AsType[*apperrors.DatabaseError](err)
			if !ok || dbErr.Resource != "StationVoice" || dbErr.Operation != apperrors.OpUpdate.String() || !errors.Is(err, cause) {
				t.Fatalf("ProcessJingle() = %v, want a StationVoice update database error caused by %v", err, cause)
			}
			path := utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID)
			if tt.beginFails {
				assertJingleContent(t, service, stationVoice, existing)
			} else {
				if !strings.Contains(errors.Unwrap(err).Error(), path) {
					t.Fatalf("commit failure cause %q does not name %s", errors.Unwrap(err), path)
				}
				// #nosec G304 - canonical jingle path inside t.TempDir.
				if got, err := os.ReadFile(path); err != nil || bytes.Equal(got, existing) {
					t.Fatalf("jingle after commit failure: %v, still the old bytes = %v; want the new jingle published", err, bytes.Equal(got, existing))
				}
			}
			assertNoProcessingJingles(t, service, stationVoice)
		})
	}
}

func TestStationVoiceService_ConcurrentJingleRequestsPublishOwnFiles(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		otherFails bool
	}{
		{"other request fails", true},
		{"other request succeeds", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := &jingleAudioRepository{}
			service, stationVoice := newJingleTestService(t, repo)
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=440:duration=1")
			otherInput := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=2")
			existing := seedJingle(t, service, stationVoice)
			expectedPath := filepath.Join(t.TempDir(), "expected.wav")
			if err := service.audioSvc.ConvertJingleToWAV(t.Context(), input, expectedPath); err != nil {
				t.Fatal(err)
			}
			// #nosec G304 - converted fixture inside t.TempDir.
			expected, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatal(err)
			}

			// Interleave the other upload between conversion and publication.
			repo.update = func() {
				repo.update = nil
				assertJingleContent(t, service, stationVoice, existing)
				var wantErr error
				if tt.otherFails {
					wantErr = errors.New("database down")
				}
				repo.err = wantErr
				if err := service.ProcessJingle(t.Context(), stationVoice, otherInput); !errors.Is(err, wantErr) {
					t.Fatalf("other request = %v, want %v", err, wantErr)
				}
				repo.err = nil
				if tt.otherFails {
					assertJingleContent(t, service, stationVoice, existing)
				}
			}
			if err := service.ProcessJingle(t.Context(), stationVoice, input); err != nil {
				t.Fatalf("first request = %v, want success", err)
			}
			// The first request publishes last and must publish its own bytes.
			assertJingleContent(t, service, stationVoice, expected)
			filename := utils.JingleFilename(stationVoice.StationID, stationVoice.VoiceID)
			if repo.id != stationVoice.ID || repo.audioFile != filename {
				t.Fatalf("row = %d, %q; want %d, %q", repo.id, repo.audioFile, stationVoice.ID, filename)
			}
			assertUmaskMode(t, utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID))
			assertNoProcessingJingles(t, service, stationVoice)
		})
	}
}

func TestStationVoiceService_JingleRenameFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		hasJingle bool
	}{
		{"replacement", true},
		{"first upload", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := &jingleAudioRepository{}
			service, stationVoice := newJingleTestService(t, repo)
			input := lavfiFixture(t, service.config.Audio.FFmpegPath, "sine=frequency=880:duration=1")
			var existing []byte
			if tt.hasJingle {
				existing = seedJingle(t, service, stationVoice)
			}
			repo.update = func() {
				paths, err := filepath.Glob(filepath.Join(service.config.Audio.ProcessedPath, "*.processing", "*"))
				if err != nil || len(paths) != 1 {
					t.Fatalf("conversion files = %v, %v; want one", paths, err)
				}
				if err := os.Remove(paths[0]); err != nil {
					t.Fatal(err)
				}
			}
			err := service.ProcessJingle(t.Context(), stationVoice, input)
			_, isDatabaseErr := errors.AsType[*apperrors.DatabaseError](err)
			if audioErr, ok := errors.AsType[*apperrors.AudioError](err); !ok || audioErr.Operation != "finalize" || isDatabaseErr {
				t.Fatalf("ProcessJingle() = %v, want finalize error", err)
			}
			if !service.txManager.(*jingleTxManager).rolledBack {
				t.Fatal("row update was not rolled back")
			}
			path := utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID)
			if tt.hasJingle {
				assertJingleContent(t, service, stationVoice, existing)
			} else if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("first upload after rename failure: %v, want no jingle", err)
			}
			assertNoProcessingJingles(t, service, stationVoice)
		})
	}
}

func newJingleTestService(t *testing.T, repo stationVoiceRepository) (*StationVoiceService, *models.StationVoice) {
	t.Helper()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	cfg := &config.Config{Audio: config.AudioConfig{
		FFmpegPath: ffmpegPath, FFprobePath: ffprobePath, ProcessedPath: t.TempDir(),
	}}
	service := &StationVoiceService{
		txManager:        &jingleTxManager{},
		stationVoiceRepo: repo,
		audioSvc:         audio.NewService(cfg, nil),
		config:           cfg,
		alerts:           notify.Discard,
	}
	return service, &models.StationVoice{ID: 3, StationID: 1, VoiceID: 2}
}

func seedJingle(t *testing.T, service *StationVoiceService, stationVoice *models.StationVoice) []byte {
	t.Helper()
	data := []byte("existing jingle must stay intact")
	// #nosec G703 - storage root and numeric IDs are controlled by the test.
	if err := os.WriteFile(utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func assertJingleContent(t *testing.T, service *StationVoiceService, stationVoice *models.StationVoice, want []byte) {
	t.Helper()
	// #nosec G304 - canonical jingle path inside t.TempDir.
	got, err := os.ReadFile(utils.JinglePath(service.config, stationVoice.StationID, stationVoice.VoiceID))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("jingle: %v, bytes match = %v; want the expected bytes", err, bytes.Equal(got, want))
	}
}

// assertNoProcessingJingles fails when anything but the live jingle remains.
func assertNoProcessingJingles(t *testing.T, service *StationVoiceService, stationVoice *models.StationVoice) {
	t.Helper()
	entries, err := os.ReadDir(service.config.Audio.ProcessedPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || entry.Name() != utils.JingleFilename(stationVoice.StationID, stationVoice.VoiceID) {
			t.Fatalf("leftover %q, want only the live jingle", entry.Name())
		}
	}
}
