package config

import (
	"os"
	"strings"
	"testing"
)

func TestValidateRequiresFFmpeg(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)
	cfg.Audio.FFmpegPath = "/definitely/missing/ffmpeg"

	err := cfg.Validate()
	assertErrorContains(t, err, "FFmpeg binary not found", "/definitely/missing/ffmpeg", "BABBEL_FFMPEG_PATH")
}

func TestValidateRequiresFFprobe(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)
	cfg.Audio.FFprobePath = "/definitely/missing/ffprobe"

	err := cfg.Validate()
	assertErrorContains(t, err, "FFprobe binary not found", "/definitely/missing/ffprobe", "BABBEL_FFPROBE_PATH")
}

func TestValidateAcceptsConfiguredAudioTools(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func validTestConfig(t *testing.T) *Config {
	t.Helper()

	executablePath, err := os.Executable()
	if err != nil {
		t.Fatalf("test executable path: %v", err)
	}

	return &Config{
		Database: DatabaseConfig{
			Port: 3306,
		},
		Auth: AuthConfig{
			Method:        AuthMethodLocal,
			SessionSecret: strings.Repeat("x", 32),
		},
		Audio: AudioConfig{
			FFmpegPath:  executablePath,
			FFprobePath: executablePath,
		},
		Environment: EnvDevelopment,
	}
}

func assertErrorContains(t *testing.T, err error, parts ...string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error")
	}

	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("expected error to contain %q, got: %v", part, err)
		}
	}
}
