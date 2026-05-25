package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRequiresAudioToolPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name:    "empty ffmpeg path",
			config:  validConfigWithAudioTools("", writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffprobe"))),
			wantErr: "BABBEL_FFMPEG_PATH must not be empty",
		},
		{
			name:    "empty ffprobe path",
			config:  validConfigWithAudioTools(writeVersionExecutable(t, filepath.Join(t.TempDir(), "ffmpeg")), ""),
			wantErr: "BABBEL_FFPROBE_PATH must not be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertErrorContains(t, tt.config.Validate(), tt.wantErr)
		})
	}
}

func TestValidateRequiresFFmpeg(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig(t)
	cfg.Audio.FFmpegPath = filepath.Join(t.TempDir(), "missing-ffmpeg")
	assertErrorContains(t, cfg.Validate(), "FFmpeg binary not found", cfg.Audio.FFmpegPath, "BABBEL_FFMPEG_PATH")
}

func TestValidateRequiresFFprobe(t *testing.T) {
	t.Parallel()
	cfg := validTestConfig(t)
	cfg.Audio.FFprobePath = filepath.Join(t.TempDir(), "missing-ffprobe")
	assertErrorContains(t, cfg.Validate(), "FFprobe binary not found", cfg.Audio.FFprobePath, "BABBEL_FFPROBE_PATH")
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

func TestValidateDatabasePoolConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "max open connections too low",
			mutate: func(cfg *Config) {
				cfg.Database.MaxOpenConns = 0
			},
			wantErr: "BABBEL_DB_MAX_OPEN_CONNS must be >= 1",
		},
		{
			name: "max idle connections negative",
			mutate: func(cfg *Config) {
				cfg.Database.MaxIdleConns = -1
			},
			wantErr: "BABBEL_DB_MAX_IDLE_CONNS must be >= 0",
		},
		{
			name: "max idle connections exceeds max open connections",
			mutate: func(cfg *Config) {
				cfg.Database.MaxOpenConns = 5
				cfg.Database.MaxIdleConns = 6
			},
			wantErr: "BABBEL_DB_MAX_IDLE_CONNS must be <= BABBEL_DB_MAX_OPEN_CONNS",
		},
		{
			name: "connection lifetime too low",
			mutate: func(cfg *Config) {
				cfg.Database.ConnMaxLifetime = 0
			},
			wantErr: "BABBEL_DB_CONN_MAX_LIFETIME must be > 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validTestConfig(t)
			tt.mutate(cfg)

			err := cfg.Validate()
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateLocalAuthConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "minimum password length below fixed HTTP floor",
			mutate: func(cfg *Config) {
				cfg.Auth.Local.MinPasswordLength = 7
			},
			wantErr: "BABBEL_AUTH_MIN_PASSWORD_LENGTH must be between 8 and 128",
		},
		{
			name: "minimum password length above HTTP maximum",
			mutate: func(cfg *Config) {
				cfg.Auth.Local.MinPasswordLength = 129
			},
			wantErr: "BABBEL_AUTH_MIN_PASSWORD_LENGTH must be between 8 and 128",
		},
		{
			name: "max login attempts too low",
			mutate: func(cfg *Config) {
				cfg.Auth.Local.MaxLoginAttempts = 0
			},
			wantErr: "BABBEL_AUTH_MAX_LOGIN_ATTEMPTS must be >= 1",
		},
		{
			name: "lockout duration too low",
			mutate: func(cfg *Config) {
				cfg.Auth.Local.LockoutDurationMinutes = 0
			},
			wantErr: "BABBEL_AUTH_LOCKOUT_MINUTES must be >= 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validTestConfig(t)
			tt.mutate(cfg)

			err := cfg.Validate()
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateSkipsLocalAuthConfigForOIDCOnly(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig(t)
	cfg.Auth.Method = AuthMethodOIDC
	cfg.Auth.OIDCProviderURL = "https://example.com"
	cfg.Auth.OIDCClientID = "client-id"
	cfg.Auth.OIDCClientSecret = "client-secret"
	cfg.Auth.Local.MaxLoginAttempts = 0
	cfg.Auth.Local.LockoutDurationMinutes = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestValidateAllowedOrigins(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name    string
		origins string
	}{
		{name: "empty disables CORS", origins: ""},
		{name: "single origin", origins: "https://app.example.com"},
		{name: "origin with port", origins: "http://localhost:3000"},
		{name: "trailing slash tolerated", origins: "https://app.example.com/"},
		{name: "multiple origins with whitespace", origins: "https://app.example.com, http://localhost:3000"},
	}

	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validTestConfig(t)
			cfg.Server.AllowedOrigins = tt.origins

			if err := cfg.Validate(); err != nil {
				t.Fatalf("unexpected error for origins %q: %v", tt.origins, err)
			}
		})
	}

	invalid := []struct {
		name    string
		origins string
		wantErr string
	}{
		{name: "missing scheme", origins: "app.example.com", wantErr: "missing scheme"},
		{name: "userinfo authority", origins: "https://app.example.com@evil.test", wantErr: "must not contain user information"},
		{name: "path component", origins: "https://app.example.com/callback", wantErr: "without path, query, or fragment"},
		{name: "multiple trailing slashes", origins: "https://app.example.com//", wantErr: "without path, query, or fragment"},
		{name: "query component", origins: "https://app.example.com?next=/x", wantErr: "without path, query, or fragment"},
		{name: "empty query marker", origins: "https://app.example.com?", wantErr: "without path, query, or fragment"},
		{name: "fragment component", origins: "https://app.example.com#frag", wantErr: "without path, query, or fragment"},
		{name: "one bad entry among valid entries", origins: "https://app.example.com, app.example.com", wantErr: "missing scheme"},
	}

	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validTestConfig(t)
			cfg.Server.AllowedOrigins = tt.origins

			err := cfg.Validate()
			assertErrorContains(t, err, "BABBEL_ALLOWED_ORIGINS", tt.wantErr)
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
			Port:            3306,
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Auth: AuthConfig{
			Method:        AuthMethodLocal,
			SessionSecret: strings.Repeat("x", 32),
			Local: LocalAuthConfig{
				MinPasswordLength:      8,
				RequireUppercase:       true,
				RequireLowercase:       true,
				RequireNumber:          true,
				MaxLoginAttempts:       5,
				LockoutDurationMinutes: 15,
			},
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
printf '%s\n' ` + shellSingleQuote(message) + ` >&2
exit 17
`
	writeExecutable(t, path, script)
	return path
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
