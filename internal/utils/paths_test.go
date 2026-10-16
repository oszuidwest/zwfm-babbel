package utils

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBulletinFilenameIncludesSubsecondPrecision(t *testing.T) {
	t.Parallel()

	first := BulletinFilename(7, time.Date(2026, 8, 18, 12, 30, 1, 1, time.UTC))
	second := BulletinFilename(7, time.Date(2026, 8, 18, 12, 30, 1, 2, time.UTC))
	if first == second {
		t.Fatalf("BulletinFilename() produced collision %q", first)
	}
}

func TestProcessingPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	finalPath := filepath.Join(root, "story_7.wav")
	first, cleanup, err := ProcessingPath(finalPath, "story_7")
	if err != nil {
		t.Fatal(err)
	}
	second, cleanupSecond, err := ProcessingPath(finalPath, "story_7")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupSecond()

	dir := filepath.Dir(first)
	if filepath.Dir(dir) != root || filepath.Base(first) != "story_7.wav" {
		t.Fatalf("ProcessingPath() = %q, want story_7.wav in a directory beside %q", first, finalPath)
	}
	if name := filepath.Base(dir); !strings.HasPrefix(name, "story_7_") || !strings.HasSuffix(name, ProcessingDirSuffix) {
		t.Fatalf("directory = %q, want story_7_*%s", name, ProcessingDirSuffix)
	}
	if filepath.Dir(second) == dir {
		t.Fatalf("concurrent requests share directory %q", dir)
	}

	// The converter creates the file, so its mode follows the umask. os.Create
	// applies the umask the same way FFmpeg does.
	info := createAndStat(t, first)
	refInfo := createAndStat(t, filepath.Join(t.TempDir(), "ref.wav"))
	if mode, want := info.Mode().Perm(), refInfo.Mode().Perm(); mode != want {
		t.Fatalf("converted mode = %v, want %v from the umask", mode, want)
	}

	cleanup()
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory after cleanup: %v, want removed", err)
	}
	if _, err := os.Stat(filepath.Dir(second)); err != nil {
		t.Fatalf("cleanup removed the other request's directory: %v", err)
	}
}

func TestProcessingPathMissingDirectory(t *testing.T) {
	t.Parallel()

	finalPath := filepath.Join(t.TempDir(), "missing", "story_7.wav")
	if _, _, err := ProcessingPath(finalPath, "story_7"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ProcessingPath() error = %v, want not exist", err)
	}
}

func createAndStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	// #nosec G304 - path inside t.TempDir.
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
	return info
}
