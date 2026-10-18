package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudioInputsUseConfiguredTempDirectory(t *testing.T) {
	osDir, ownedDir := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", osDir)
	c, rec := newAudioUploadContext(t, "audio", "clip.wav", strings.NewReader("audio"))
	upload, cleanup, ok := SaveAudioUpload(c, ownedDir, "audio", "story_42")
	if !ok {
		t.Fatalf("upload = %s", rec.Body)
	}
	t.Cleanup(func() { _ = cleanup() })
	tts, err := WriteTempFile(ownedDir, strings.NewReader("opus"), "tts_story_42_*.opus")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{upload, tts} {
		if filepath.Dir(path) != ownedDir {
			t.Fatalf("path = %q; want owned directory %q", path, ownedDir)
		}
	}
	if entries, err := os.ReadDir(osDir); err != nil || len(entries) != 0 {
		t.Fatalf("OS temp = %v, %v; want unused", entries, err)
	}
	if _, err := WriteTempFile("", strings.NewReader("opus"), "input-*"); err == nil {
		t.Fatal("empty owned directory silently used OS temp")
	}
}
