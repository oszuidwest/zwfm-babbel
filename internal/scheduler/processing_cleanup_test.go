package scheduler

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestCleanProcessingFiles(t *testing.T) {
	now := time.Date(2026, time.October, 16, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	logs := captureCleanupLogs(t)

	tests := []struct {
		name    string
		age     time.Duration
		removed bool
	}{
		{"story_42_old.processing.wav", 25 * time.Hour, true},
		{"station_1_voice_2_old.processing.wav", 25 * time.Hour, true},
		{"story_42_fresh.processing.wav", time.Minute, false},
		{"jingle_fresh.processing.wav", 23 * time.Hour, false},
		{"boundary.processing.wav", 24 * time.Hour, false},
		{"future.processing.wav", -time.Hour, false},
		{"story_42.wav", 48 * time.Hour, false},
		{"station_1_voice_2_jingle.wav", 48 * time.Hour, false},
		{"story_42.processing.wav.bak", 48 * time.Hour, false},
		{"story_42_processing.wav", 48 * time.Hour, false},
	}
	for _, tt := range tests {
		writeCleanupFile(t, filepath.Join(dir, tt.name), now.Add(-tt.age))
	}
	old := now.Add(-48 * time.Hour)
	target := filepath.Join(t.TempDir(), "outside.processing.wav")
	writeCleanupFile(t, target, old)
	link := filepath.Join(dir, "symlink.processing.wav")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "directory.processing.wav")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(subdir, "nested.processing.wav")
	writeCleanupFile(t, nested, old)
	if err := os.Chtimes(subdir, old, old); err != nil {
		t.Fatal(err)
	}

	if err := service.cleanProcessingFiles(now); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := os.Lstat(filepath.Join(dir, tt.name))
			if tt.removed {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Lstat = %v, want file removed", err)
				}
				if !strings.Contains(logs.String(), "Removed abandoned processing audio file") || !strings.Contains(logs.String(), tt.name) {
					t.Errorf("removal not logged: %s", logs.String())
				}
			} else if err != nil {
				t.Fatalf("retained file: %v", err)
			}
		})
	}
	for _, path := range []string{link, target, subdir, nested} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("protected path %s: %v", path, err)
		}
	}
}

func TestCleanProcessingFilesDirectoryErrors(t *testing.T) {
	for _, name := range []string{"missing", "not a directory", "unreadable"} {
		t.Run(name, func(t *testing.T) {
			logs := captureCleanupLogs(t)
			dir := filepath.Join(t.TempDir(), "processed")
			wantErr := os.ErrNotExist
			switch name {
			case "not a directory":
				writeCleanupFile(t, dir, time.Now())
				wantErr = nil // ENOTDIR is platform-specific; any error suffices.
			case "unreadable":
				if err := os.Mkdir(dir, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					// #nosec G302 - Test directory needs owner traversal for cleanup.
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Error(err)
					}
				})
				if _, err := os.ReadDir(dir); err == nil {
					t.Skip("directory permissions are not enforced for this user")
				}
				wantErr = os.ErrPermission
			}
			service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
			err := service.cleanProcessingFiles(time.Now())
			if err == nil || (wantErr != nil && !errors.Is(err, wantErr)) {
				t.Fatalf("cleanProcessingFiles = %v, want %v", err, wantErr)
			}
			if !strings.Contains(logs.String(), "Failed to read processed audio directory") || !strings.Contains(logs.String(), dir) {
				t.Errorf("directory failure not logged: %s", logs.String())
			}
		})
	}
}

func TestCleanProcessingFilesContinuesAfterRemovalFailure(t *testing.T) {
	logs := captureCleanupLogs(t)
	dir := t.TempDir()
	now := time.Now()
	for _, name := range []string{"a.processing.wav", "b.processing.wav"} {
		writeCleanupFile(t, filepath.Join(dir, name), now.Add(-25*time.Hour))
	}
	// #nosec G302 - Owner can read and traverse, but cannot remove the test files.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// #nosec G302 - Test directory needs owner traversal for cleanup.
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	if os.Getuid() == 0 {
		t.Skip("root can remove files despite directory permissions")
	}
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	err := service.cleanProcessingFiles(now)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cleanProcessingFiles = %v, want permission error", err)
	}
	for _, name := range []string{"a.processing.wav", "b.processing.wav"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error = %v, want failure for %s", err, name)
		}
		if !strings.Contains(logs.String(), "Failed to remove processing audio file") || !strings.Contains(logs.String(), name) {
			t.Errorf("removal failure not logged: %s", logs.String())
		}
	}
}

func TestBulletinCleanupSweepsProcessingFilesBeforeDatabaseQuery(t *testing.T) {
	// No database connection: an existing GORM error stops every query.
	db, err := gorm.Open(mysql.New(mysql.Config{
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	queryErr := errors.New("database unavailable")
	if err := db.AddError(queryErr); !errors.Is(err, queryErr) {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "story_42_abandoned.processing.wav")
	writeCleanupFile(t, path, time.Now().Add(-25*time.Hour))
	service := NewBulletinCleanupService(db, &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}, nil)
	service.runner.runOnce()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scheduled cleanup: Lstat = %v, want file removed despite database failure", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanup(t.Context()); !errors.Is(err, queryErr) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup = %v, want both storage and database failures", err)
	}
}

func captureCleanupLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	return &logs
}

func writeCleanupFile(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte("audio"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
