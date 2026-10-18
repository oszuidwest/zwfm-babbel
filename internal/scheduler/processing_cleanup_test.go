package scheduler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
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
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestCleanProcessingLeftovers(t *testing.T) {
	// Times are relative to a future now, so entries whose own mtime cannot be
	// set, such as symlinks, are already old.
	now := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	old := now.Add(-48 * time.Hour)
	dir := t.TempDir()
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	logs := testutil.CaptureLogs(t, slog.LevelInfo)

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
	records := processingLogRecords(t, logs)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := ""
			if tt.removed {
				want = "Removed abandoned audio conversion leftover"
			}
			assertProcessingLog(t, records, filepath.Join(dir, tt.name), want)
			_, err := os.Lstat(filepath.Join(dir, tt.name))
			if tt.removed {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("Lstat = %v, want leftover removed", err)
				}
			} else if err != nil {
				t.Fatalf("retained entry: %v", err)
			}
		})
	}
	for _, path := range []string{dirLink, fileLink, outsideDir, filepath.Join(outsideDir, "output.wav"), outsideFile} {
		assertProcessingLog(t, records, path, "")
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("protected path %s: %v", path, err)
		}
	}
}

func TestCleanProcessingLeftoversReportsMissingDirectory(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	dir := filepath.Join(t.TempDir(), "missing")
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	if err := service.cleanProcessingLeftovers(time.Now()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanProcessingLeftovers = %v, want ErrNotExist", err)
	}
	// Unmarshal rejects an empty buffer and a second record. Comparing the
	// decoded path keeps JSON escaping out of the check.
	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil ||
		record["msg"] != "Failed to read processed audio directory" || record["path"] != dir {
		t.Errorf("logs = %s, want one directory failure record for %s", logs, dir)
	}
}

func TestCleanProcessingLeftoversContinuesAfterRemovalFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can remove files despite directory permissions")
	}
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	dir := t.TempDir()
	now := time.Now()
	writeCleanupDir(t, filepath.Join(dir, "a.processing"), now.Add(-25*time.Hour))
	writeCleanupFile(t, filepath.Join(dir, "b.processing.wav"), now.Add(-25*time.Hour))
	// #nosec G302 - Owner can read and traverse, but cannot remove the test entries.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// #nosec G302 - Restore owner write so TempDir cleanup can remove the entries.
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	err := service.cleanProcessingLeftovers(now)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cleanProcessingLeftovers = %v, want permission error", err)
	}
	records := processingLogRecords(t, logs)
	for _, name := range []string{"a.processing", "b.processing.wav"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error = %v, want failure for %s", err, name)
		}
		assertProcessingLog(t, records, filepath.Join(dir, name), "Failed to remove audio conversion leftover")
	}
}

// processingLogRecords decodes each JSON record so message and path assertions
// always refer to the same record.
func processingLogRecords(t *testing.T, logs *bytes.Buffer) []map[string]any {
	t.Helper()
	var records []map[string]any
	for line := range bytes.Lines(logs.Bytes()) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid log record %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

// assertProcessingLog requires exactly one record for path with message, or
// no record for path when message is empty (a retained entry).
func assertProcessingLog(t *testing.T, records []map[string]any, path, message string) {
	t.Helper()
	count := 0
	for _, record := range records {
		if record["path"] == path {
			count++
			if message == "" || record["msg"] != message {
				t.Errorf("unexpected log for %s: %v; want message %q", path, record, message)
			}
		}
	}
	if message != "" && count != 1 {
		t.Errorf("logs for %s = %d, want exactly one with message %q", path, count, message)
	}
}

func TestCleanProcessingLeftoversSkipsVanishedEntries(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	dir := t.TempDir()
	now := time.Now()
	vanished := []string{"a.processing", "b.processing.wav"}
	writeCleanupDir(t, filepath.Join(dir, vanished[0]), now.Add(-25*time.Hour))
	writeCleanupFile(t, filepath.Join(dir, vanished[1]), now.Add(-25*time.Hour))
	kept := filepath.Join(dir, "c.processing")
	writeCleanupDir(t, kept, now.Add(-25*time.Hour))
	t.Cleanup(func() { processingEntryInfo = fs.DirEntry.Info })
	// The owning requests remove their entries after ReadDir.
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

func TestCleanProcessingLeftoversReportsStatFailure(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	dir := t.TempDir()
	now := time.Now()
	failed := filepath.Join(dir, "a.processing")
	writeCleanupDir(t, failed, now.Add(-25*time.Hour))
	kept := filepath.Join(dir, "b.processing")
	writeCleanupDir(t, kept, now.Add(-25*time.Hour))
	t.Cleanup(func() { processingEntryInfo = fs.DirEntry.Info })
	processingEntryInfo = func(entry fs.DirEntry) (fs.FileInfo, error) {
		if entry.Name() == "a.processing" {
			return nil, fs.ErrPermission
		}
		return entry.Info()
	}

	service := &BulletinCleanupService{config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
	err := service.cleanProcessingLeftovers(now)
	if !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), failed) {
		t.Fatalf("cleanProcessingLeftovers = %v, want stat failure for %s", err, failed)
	}
	// Comparing the decoded path keeps JSON escaping out of the check.
	if !slices.ContainsFunc(bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")), func(line []byte) bool {
		var record map[string]any
		return json.Unmarshal(line, &record) == nil &&
			record["msg"] == "Failed to stat audio conversion leftover" && record["path"] == failed
	}) {
		t.Errorf("stat failure not logged: %s", logs)
	}
	if _, err := os.Lstat(kept); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat = %v, want remaining leftover removed", err)
	}
}

func TestBulletinCleanupSweepsProcessingLeftoversBeforeDatabaseQuery(t *testing.T) {
	// An existing GORM error stops every query.
	db := offlineDB(t)
	queryErr := errors.New("database unavailable")
	if err := db.AddError(queryErr); !errors.Is(err, queryErr) {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "story_42_123.processing")
	writeCleanupDir(t, path, time.Now().Add(-25*time.Hour))
	service := NewBulletinCleanupService(db, &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}, nil)
	if err := service.cleanup(t.Context()); !errors.Is(err, queryErr) {
		t.Fatalf("cleanup = %v, want database failure", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lstat = %v, want leftover removed despite database failure", err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := service.cleanup(t.Context()); !errors.Is(err, queryErr) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup = %v, want both storage and database failures", err)
	}
}

func TestBulletinCleanupReportsProcessingFailureAfterDatabaseSuccess(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Audio: config.AudioConfig{ProcessedPath: filepath.Join(dir, "missing"), OutputPath: dir}}
	service := NewBulletinCleanupService(offlineDB(t), cfg, nil)
	err := service.cleanup(t.Context())
	if pathErr, ok := errors.AsType[*fs.PathError](err); !ok || pathErr.Path != cfg.Audio.ProcessedPath {
		t.Fatalf("cleanup = %v, want processed audio directory failure", err)
	}
}

// offlineDB returns a GORM handle whose queries succeed without rows and never
// reach a server: DryRun builds statements without running them, and the
// skipped default transaction keeps deletes from connecting. The DSN names a
// socket that does not exist, so a query that does connect fails fast.
func offlineDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "babbel@unix(" + filepath.Join(t.TempDir(), "none.sock") + ")/babbel",
		SkipInitializeWithVersion: true,
	}), &gorm.Config{DryRun: true, DisableAutomaticPing: true, SkipDefaultTransaction: true})
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
	return db
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
