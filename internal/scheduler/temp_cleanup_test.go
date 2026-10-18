package scheduler

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestCleanInputLeftovers(t *testing.T) {
	now := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	dir := t.TempDir()
	for _, name := range []string{"story_42_old.wav", "tts_story_42_old.opus"} {
		writeCleanupFile(t, filepath.Join(dir, name), now.Add(-25*time.Hour))
	}
	writeCleanupFile(t, filepath.Join(dir, "station_1_voice_2_recent.wav"), now.Add(-time.Hour))
	writeCleanupFile(t, filepath.Join(dir, "exact-boundary.opus"), now.Add(-24*time.Hour))
	writeCleanupDir(t, filepath.Join(dir, "old-directory"), now.Add(-25*time.Hour))
	outside := filepath.Join(t.TempDir(), "outside.wav")
	writeCleanupFile(t, outside, now.Add(-25*time.Hour))
	if err := os.Symlink(outside, filepath.Join(dir, "old-symlink")); err != nil {
		t.Fatal(err)
	}
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	s := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{TempPath: dir}}}
	if err := s.cleanInputLeftovers(now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"story_42_old.wav", "tts_story_42_old.opus"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("old file %s = %v", name, err)
		}
	}
	for _, path := range []string{outside, filepath.Join(dir, "old-directory"), filepath.Join(dir, "old-symlink"), filepath.Join(dir, "station_1_voice_2_recent.wav"), filepath.Join(dir, "exact-boundary.opus")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("kept path %s = %v", path, err)
		}
	}
	assertInputRemovalLogs(t, logs.String(), dir)
}

func assertInputRemovalLogs(t *testing.T, logs, dir string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs), "\n")
	if len(lines) != 2 {
		t.Fatalf("logs = %s; want one record per removed input", logs)
	}
	for _, line := range lines {
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) != nil || record["level"] != "INFO" || record["msg"] != "Removed abandoned audio input" ||
			(record["path"] != filepath.Join(dir, "story_42_old.wav") && record["path"] != filepath.Join(dir, "tts_story_42_old.opus")) {
			t.Fatalf("record = %s", line)
		}
	}
}

func TestCleanupSweepsInputsEvenWhenDatabaseFails(t *testing.T) {
	db := offlineDB(t)
	cause := errors.New("database unavailable")
	_ = db.AddError(cause)
	dir := t.TempDir()
	path := filepath.Join(dir, "tts_story_42_old.opus")
	writeCleanupFile(t, path, time.Now().Add(-25*time.Hour))
	s := NewBulletinCleanupService(db, &config.Config{Audio: config.AudioConfig{ProcessedPath: t.TempDir(), TempPath: dir}}, nil)
	if err := s.cleanup(t.Context()); !errors.Is(err, cause) {
		t.Fatalf("cleanup = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old input remains: %v", err)
	}
}

// Published audio is a regular file too: never sweep a persistent directory,
// even through a symlinked alias.
func TestCleanInputLeftoversRefusesPersistentDirectories(t *testing.T) {
	now := time.Now().Add(72 * time.Hour)
	for _, field := range []string{"processed", "output"} {
		t.Run(field, func(t *testing.T) {
			persistent := t.TempDir()
			published := filepath.Join(persistent, "story_42.wav")
			writeCleanupFile(t, published, now.Add(-25*time.Hour))
			alias := filepath.Join(t.TempDir(), "temp")
			if err := os.Symlink(persistent, alias); err != nil {
				t.Fatal(err)
			}
			audio := config.AudioConfig{TempPath: alias, ProcessedPath: t.TempDir(), OutputPath: t.TempDir()}
			if field == "processed" {
				audio.ProcessedPath = persistent
			} else {
				audio.OutputPath = persistent
			}
			testutil.CaptureLogs(t, slog.LevelInfo)
			s := &BulletinCleanupService{config: &config.Config{Audio: audio}}
			if err := s.cleanInputLeftovers(now); err == nil {
				t.Fatal("cleanInputLeftovers = nil, want a refusal")
			}
			if _, err := os.Lstat(published); err != nil {
				t.Fatalf("published audio: %v", err)
			}
		})
	}
}

// A file replaced by a directory after ReadDir is skipped, never removed
// recursively.
func TestCleanInputLeftoversSkipsEntryReplacedByDirectory(t *testing.T) {
	now := time.Now().Add(72 * time.Hour)
	dir := t.TempDir()
	path := filepath.Join(dir, "input.wav")
	writeCleanupFile(t, path, now.Add(-25*time.Hour))
	kept := filepath.Join(path, "kept.wav")
	t.Cleanup(func() { processingEntryInfo = fs.DirEntry.Info })
	processingEntryInfo = func(entry fs.DirEntry) (fs.FileInfo, error) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		writeCleanupDir(t, path, now.Add(-25*time.Hour))
		writeCleanupFile(t, kept, now.Add(-25*time.Hour))
		return entry.Info()
	}
	testutil.CaptureLogs(t, slog.LevelInfo)
	s := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{TempPath: dir}}}
	if err := s.cleanInputLeftovers(now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(kept); err != nil {
		t.Fatalf("file inside the replacing directory: %v", err)
	}
}
