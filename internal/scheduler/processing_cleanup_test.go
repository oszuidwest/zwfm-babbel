package scheduler

import (
	"bytes"
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestCleanProcessingLeftovers(t *testing.T) {
	// Times are relative to a future now, so entries whose own mtime cannot be
	// set, such as symlinks, are already old.
	now := time.Now().Add(72 * time.Hour)
	old := now.Add(-48 * time.Hour)
	dir := t.TempDir()
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	logs := captureCleanupLogs(t)

	tests := []struct {
		name    string
		isDir   bool
		age     time.Duration
		removed bool
	}{
		{"story_42_123.processing", true, 25 * time.Hour, true},
		{"station_1_voice_2_456.processing", true, 25 * time.Hour, true},
		{"story_42.processing.wav", false, 25 * time.Hour, true},
		{"story_42_in_flight.processing", true, time.Minute, false},
		{"story_42_almost.processing", true, 23 * time.Hour, false},
		{"story_42_boundary.processing", true, 24 * time.Hour, false},
		{"story_42_future.processing", true, -time.Hour, false},
		{"story_42.wav", false, 48 * time.Hour, false},
		{"station_1_voice_2_jingle.wav", false, 48 * time.Hour, false},
		{"file.processing", false, 48 * time.Hour, false},
		{"directory.processing.wav", true, 48 * time.Hour, false},
		{"story_42.processing.bak", true, 48 * time.Hour, false},
		{"story_42_processing.wav", false, 48 * time.Hour, false},
	}
	for _, tt := range tests {
		path := filepath.Join(dir, tt.name)
		if tt.isDir {
			writeCleanupDir(t, path, now.Add(-tt.age))
		} else {
			writeCleanupFile(t, path, now.Add(-tt.age))
		}
	}

	// Links to old leftovers outside ProcessedPath, at the top level and
	// inside an old directory that is removed.
	outside := t.TempDir()
	outsideDir := filepath.Join(outside, "target.processing")
	writeCleanupDir(t, outsideDir, old)
	outsideFile := filepath.Join(outside, "target.processing.wav")
	writeCleanupFile(t, outsideFile, old)
	dirLink := filepath.Join(dir, "link.processing")
	fileLink := filepath.Join(dir, "link.processing.wav")
	nestedLink := filepath.Join(dir, "story_42_123.processing", "link.wav")
	for link, target := range map[string]string{dirLink: outsideDir, fileLink: outsideFile, nestedLink: outsideFile} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(filepath.Dir(nestedLink), old, old); err != nil {
		t.Fatal(err)
	}

	if err := service.cleanProcessingLeftovers(now); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := os.Lstat(filepath.Join(dir, tt.name))
			if tt.removed {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Lstat = %v, want leftover removed", err)
				}
				if !strings.Contains(logs.String(), "Removed abandoned audio conversion leftover") || !strings.Contains(logs.String(), tt.name) {
					t.Errorf("removal not logged: %s", logs.String())
				}
			} else if err != nil {
				t.Fatalf("retained entry: %v", err)
			}
		})
	}
	for _, path := range []string{dirLink, fileLink, outsideDir, filepath.Join(outsideDir, "output.wav"), outsideFile} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("protected path %s: %v", path, err)
		}
	}
}

func TestCleanProcessingLeftoversDirectoryErrors(t *testing.T) {
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
			err := service.cleanProcessingLeftovers(time.Now())
			if err == nil || (wantErr != nil && !errors.Is(err, wantErr)) {
				t.Fatalf("cleanProcessingLeftovers = %v, want %v", err, wantErr)
			}
			if !strings.Contains(logs.String(), "Failed to read processed audio directory") || !strings.Contains(logs.String(), dir) {
				t.Errorf("directory failure not logged: %s", logs.String())
			}
		})
	}
}

func TestCleanProcessingLeftoversContinuesAfterRemovalFailure(t *testing.T) {
	logs := captureCleanupLogs(t)
	dir := t.TempDir()
	now := time.Now()
	writeCleanupDir(t, filepath.Join(dir, "a.processing"), now.Add(-25*time.Hour))
	writeCleanupFile(t, filepath.Join(dir, "b.processing.wav"), now.Add(-25*time.Hour))
	// #nosec G302 - Owner can read and traverse, but cannot remove the test entries.
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
	err := service.cleanProcessingLeftovers(now)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cleanProcessingLeftovers = %v, want permission error", err)
	}
	for _, name := range []string{"a.processing", "b.processing.wav"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error = %v, want failure for %s", err, name)
		}
		if !strings.Contains(logs.String(), "Failed to remove audio conversion leftover") || !strings.Contains(logs.String(), name) {
			t.Errorf("removal failure not logged: %s", logs.String())
		}
	}
}

func TestCleanProcessingLeftoversSkipsVanishedEntries(t *testing.T) {
	logs := captureCleanupLogs(t)
	dir := t.TempDir()
	now := time.Now()
	vanished := []string{"a.processing", "b.processing.wav"}
	writeCleanupDir(t, filepath.Join(dir, vanished[0]), now.Add(-25*time.Hour))
	writeCleanupFile(t, filepath.Join(dir, vanished[1]), now.Add(-25*time.Hour))
	kept := filepath.Join(dir, "c.processing")
	writeCleanupDir(t, kept, now.Add(-25*time.Hour))
	// The owning requests remove their entries after ReadDir.
	t.Cleanup(func() { processingEntryInfo = fs.DirEntry.Info })
	processingEntryInfo = func(entry fs.DirEntry) (fs.FileInfo, error) {
		if slices.Contains(vanished, entry.Name()) {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
		return entry.Info()
	}

	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	if err := service.cleanProcessingLeftovers(now); err != nil {
		t.Fatalf("cleanProcessingLeftovers = %v, want vanished entries skipped", err)
	}
	for _, name := range vanished {
		if strings.Contains(logs.String(), name) {
			t.Errorf("vanished entry %s logged: %s", name, logs.String())
		}
	}
	if _, err := os.Lstat(kept); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat = %v, want remaining leftover removed", err)
	}
}

func TestBulletinCleanupSweepsProcessingLeftoversBeforeDatabaseQuery(t *testing.T) {
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
	path := filepath.Join(dir, "story_42_123.processing")
	writeCleanupDir(t, path, time.Now().Add(-25*time.Hour))
	service := NewBulletinCleanupService(db, &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}, nil)
	service.runner.runOnce()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scheduled cleanup: Lstat = %v, want leftover removed despite database failure", err)
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
	previous, previousWriter, previousFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	// SetDefault also redirects the log package, and restoring the built-in
	// default handler does not undo that.
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})
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

// writeCleanupDir creates a conversion directory holding an output file.
func writeCleanupDir(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	writeCleanupFile(t, filepath.Join(path, "output.wav"), mtime)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
