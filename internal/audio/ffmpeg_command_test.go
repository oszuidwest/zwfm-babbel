package audio

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// newScriptService returns a Service whose FFmpeg binary is a shell script
// with the given body.
func newScriptService(t *testing.T, body string) *Service {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not executable on windows")
	}
	path := filepath.Join(t.TempDir(), "ffmpeg")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // Test executable.
		t.Fatal(err)
	}
	return NewService(&config.Config{Audio: config.AudioConfig{FFmpegPath: path}}, nil)
}

func TestExecuteFFmpegCommandMissingExecutable(t *testing.T) {
	t.Parallel()
	svc := NewService(&config.Config{
		Audio: config.AudioConfig{FFmpegPath: filepath.Join(t.TempDir(), "missing-ffmpeg")},
	}, nil)

	err := svc.executeFFmpegCommand(t.Context(), nil)
	if err == nil || !strings.HasPrefix(err.Error(), "failed to start ffmpeg:") {
		t.Fatalf("error = %v, want start failure", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want os.ErrNotExist", err)
	}
}

func TestExecuteFFmpegCommandFailureKeepsStderr(t *testing.T) {
	t.Parallel()
	svc := newScriptService(t, "echo 'Invalid filter graph' >&2\nexit 3")

	err := svc.executeFFmpegCommand(t.Context(), nil)
	if err == nil || !strings.Contains(err.Error(), "stderr: Invalid filter graph") {
		t.Fatalf("error = %v, want FFmpeg stderr diagnostics", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, must not report cancellation", err)
	}
}

func TestExecuteFFmpegCommandCanceledContext(t *testing.T) {
	t.Parallel()
	// exec replaces the shell so killing the process closes stderr.
	svc := newScriptService(t, "exec sleep 30")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()

	err := svc.executeFFmpegCommand(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
