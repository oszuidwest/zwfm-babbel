package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRequiresAudioToolPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name: "empty ffmpeg path",
			config: validConfigWithAudioTools(
				"",
				writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffprobe")),
			),
			wantErr: "BABBEL_FFMPEG_PATH must not be empty",
		},
		{
			name: "empty ffprobe path",
			config: validConfigWithAudioTools(
				writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffmpeg")),
				"",
			),
			wantErr: "BABBEL_FFPROBE_PATH must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateRequiresFFmpeg(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)
	cfg.Audio.FFmpegPath = filepath.Join(t.TempDir(), "missing-ffmpeg")

	err := cfg.Validate()
	assertErrorContains(t, err, "FFmpeg binary not found", cfg.Audio.FFmpegPath, "BABBEL_FFMPEG_PATH")
}

func TestValidateRequiresFFprobe(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)
	cfg.Audio.FFprobePath = filepath.Join(t.TempDir(), "missing-ffprobe")

	err := cfg.Validate()
	assertErrorContains(t, err, "FFprobe binary not found", cfg.Audio.FFprobePath, "BABBEL_FFPROBE_PATH")
}

func TestValidateAcceptsConfiguredAudioTools(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertVersionCheckRan(t, cfg.Audio.FFmpegPath)
	assertVersionCheckRan(t, cfg.Audio.FFprobePath)
}

func TestValidateAcceptsBinariesFromPATH(t *testing.T) {
	dir := t.TempDir()
	ffmpegPath := writeVersionExecutable(t, filepath.Join(dir, "ffmpeg"))
	ffprobePath := writeVersionExecutable(t, filepath.Join(dir, "ffprobe"))
	t.Setenv("PATH", dir)

	cfg := validConfigWithAudioTools("ffmpeg", "ffprobe")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertVersionCheckRan(t, ffmpegPath)
	assertVersionCheckRan(t, ffprobePath)
}

func TestValidateRequiresRunnableAudioTools(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		config       *Config
		wantContains []string
	}{
		{
			name: "ffmpeg version check fails",
			config: validConfigWithAudioTools(
				writeFailingVersionExecutable(t, filepath.Join(t.TempDir(), "ffmpeg"), "bad ffmpeg"),
				writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffprobe")),
			),
			wantContains: []string{
				"FFmpeg binary",
				"failed -version check",
				"bad ffmpeg",
				"BABBEL_FFMPEG_PATH",
			},
		},
		{
			name: "ffprobe version check fails",
			config: validConfigWithAudioTools(
				writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffmpeg")),
				writeFailingVersionExecutable(t, filepath.Join(t.TempDir(), "ffprobe"), "bad ffprobe"),
			),
			wantContains: []string{
				"FFprobe binary",
				"failed -version check",
				"bad ffprobe",
				"BABBEL_FFPROBE_PATH",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.config.Validate()
			assertErrorContains(t, err, tt.wantContains...)
		})
	}
}

func validTestConfig(t *testing.T) *Config {
	t.Helper()

	dir := t.TempDir()
	ffmpegPath := writeVersionExecutable(t, filepath.Join(dir, "ffmpeg"))
	ffprobePath := writeVersionExecutable(t, filepath.Join(dir, "ffprobe"))

	return validConfigWithAudioTools(ffmpegPath, ffprobePath)
}

func validConfigWithAudioTools(ffmpegPath, ffprobePath string) *Config {
	return &Config{
		Database: DatabaseConfig{
			Port: 3306,
		},
		Auth: AuthConfig{
			Method:        AuthMethodLocal,
			SessionSecret: strings.Repeat("x", 32),
		},
		Audio: AudioConfig{
			FFmpegPath:  ffmpegPath,
			FFprobePath: ffprobePath,
		},
		Environment: EnvDevelopment,
	}
}

func writeVersionExecutable(t *testing.T, path string) string {
	t.Helper()

	const script = `#!/bin/sh
if [ "$1" != "-version" ]; then
	echo "expected -version" >&2
	exit 42
fi
printf '%s\n' "$1" > "$0.called"
exit 0
`
	writeExecutable(t, path, script)
	return path
}

func writeFailingVersionExecutable(t *testing.T, path, message string) string {
	t.Helper()

	script := `#!/bin/sh
if [ "$1" != "-version" ]; then
	echo "expected -version" >&2
	exit 42
fi
echo "` + message + `" >&2
exit 17
`
	writeExecutable(t, path, script)
	return path
}

func writeExecutable(t *testing.T, path, contents string) {
	t.Helper()

	// #nosec G306 - Test helper writes an executable script under t.TempDir().
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func assertVersionCheckRan(t *testing.T, path string) {
	t.Helper()

	// #nosec G304 - Marker path is derived from a test executable written under t.TempDir().
	data, err := os.ReadFile(path + ".called")
	if err != nil {
		t.Fatalf("read version check marker: %v", err)
	}

	if got := strings.TrimSpace(string(data)); got != "-version" {
		t.Fatalf("version check marker = %q, want -version", got)
	}
}

func assertErrorContains(t *testing.T, err error, parts ...string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error")
	}

	failed := false
	for _, part := range parts {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("expected error to contain %q, got: %v", part, err)
			failed = true
		}
	}

	if failed {
		t.FailNow()
	}
}
