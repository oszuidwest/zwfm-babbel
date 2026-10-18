package utils

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
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

func TestParseJingleFilename(t *testing.T) {
	t.Parallel()

	if stationID, voiceID, ok := ParseJingleFilename(JingleFilename(12, 345)); !ok || stationID != 12 || voiceID != 345 {
		t.Fatalf("ParseJingleFilename(JingleFilename(12, 345)) = %d, %d, %v; want 12, 345, true", stationID, voiceID, ok)
	}
	for _, filename := range []string{
		"",
		"story_1.wav",
		"../station_1_voice_2_jingle.wav",
		"/tmp/station_1_voice_2_jingle.wav",
		"sub/station_1_voice_2_jingle.wav",
		"station_01_voice_2_jingle.wav",
		"station_+1_voice_2_jingle.wav",
		"station_0_voice_2_jingle.wav",
		"station_-1_voice_2_jingle.wav",
		"station_1_voice_2_jingle.wav.bak",
		"station_1_voice_2_jingle.mp3",
	} {
		if stationID, voiceID, ok := ParseJingleFilename(filename); ok {
			t.Errorf("ParseJingleFilename(%q) = %d, %d, true; want false", filename, stationID, voiceID)
		}
	}
}

func TestProcessingPath(t *testing.T) {
	t.Parallel()

	// Jingle-shaped arguments: name differs from finalPath's stem, so this
	// fails if the directory name is derived from finalPath.
	root := t.TempDir()
	finalPath := filepath.Join(root, "station_1_voice_2_jingle.wav")
	first, cleanup, err := ProcessingPath(finalPath, "station_1_voice_2")
	if err != nil {
		t.Fatal(err)
	}
	second, cleanupSecond, err := ProcessingPath(finalPath, "station_1_voice_2")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupSecond()

	dir := filepath.Dir(first)
	if filepath.Dir(dir) != root || filepath.Base(first) != "station_1_voice_2_jingle.wav" {
		t.Fatalf("ProcessingPath() = %q, want station_1_voice_2_jingle.wav in a directory beside %q", first, finalPath)
	}
	if name := filepath.Base(dir); !regexp.MustCompile(`^station_1_voice_2_[^_]+\.processing$`).MatchString(name) {
		t.Fatalf("directory = %q, want station_1_voice_2_<random>%s", name, ProcessingDirSuffix)
	}
	if filepath.Dir(second) == dir {
		t.Fatalf("concurrent requests share directory %q", dir)
	}

	// The converter creates the file, so its mode follows the umask.
	if _, err := os.Lstat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("converted file before conversion: %v, want not created", err)
	}
	// Stand in for the converted file: cleanup must remove a non-empty directory.
	if err := os.WriteFile(first, nil, 0o600); err != nil {
		t.Fatal(err)
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
