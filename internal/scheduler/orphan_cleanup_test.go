package scheduler

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

// Files published or discarded after ReadDir are already cleaned up, while
// real stat/removal failures must still be reported and leave other work running.
func TestCleanOrphanedFilesConcurrentRemoval(t *testing.T) {
	for _, tt := range []struct {
		name, stage string
		failure     error
	}{
		{name: "vanished before stat", stage: "stat"},
		{name: "vanished before remove", stage: "remove"},
		{name: "stat failed", stage: "stat", failure: fs.ErrPermission},
		{name: "remove failed", stage: "remove", failure: fs.ErrPermission},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "a.tmp.wav")
			writeCleanupFile(t, path, time.Now().Add(-2*time.Hour))
			writeCleanupFile(t, filepath.Join(dir, "b.wav"), time.Now().Add(-2*time.Hour))
			logs := testutil.CaptureLogs(t, slog.LevelInfo)
			service := NewBulletinCleanupService(offlineDB(t), &config.Config{Audio: config.AudioConfig{OutputPath: dir}}, nil)
			t.Cleanup(func() { orphanEntryInfo, orphanRemove = fs.DirEntry.Info, os.Remove })
			orphanEntryInfo = func(entry fs.DirEntry) (fs.FileInfo, error) {
				if entry.Name() == "a.tmp.wav" && tt.stage == "stat" {
					if tt.failure != nil {
						return nil, tt.failure
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				return entry.Info()
			}
			orphanRemove = func(candidate string) error {
				if candidate == path && tt.stage == "remove" {
					if tt.failure != nil {
						return tt.failure
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				return os.Remove(candidate)
			}
			removed, freed, err := service.cleanOrphanedFiles(t.Context())
			if !errors.Is(err, tt.failure) || removed != 1 || freed != 5 {
				t.Fatalf("cleanup = %d, %d, %v; want one 5-byte orphan removed and error %v", removed, freed, err, tt.failure)
			}
			assertOrphanFailureLog(t, logs.Bytes(), path, tt.stage, tt.failure)
		})
	}
}

func assertOrphanFailureLog(t *testing.T, logs []byte, path, stage string, failure error) {
	t.Helper()
	if failure == nil {
		if len(logs) != 0 {
			t.Fatalf("logs = %s, want none for vanished orphan", logs)
		}
		return
	}
	var record map[string]any
	if err := json.Unmarshal(logs, &record); err != nil || record["level"] != "ERROR" || record["path"] != path ||
		record["msg"] != "Failed to "+stage+" orphaned file" || record["error"] != failure.Error() {
		t.Fatalf("logs = %s, want one Error for %s of %s", logs, stage, path)
	}
}
