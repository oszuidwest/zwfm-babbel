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

// newShellService uses an existing executable to avoid ETXTBSY races when
// parallel tests write and execute scripts (golang/go#22315).
func newShellService(t *testing.T) *Service {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not executable on windows")
	}
	return NewService(&config.Config{Audio: config.AudioConfig{FFmpegPath: "/bin/sh"}}, nil)
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
	svc := newShellService(t)

	err := svc.executeFFmpegCommand(t.Context(), []string{"-c", "echo 'Invalid filter graph' >&2; exit 3"})
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
	svc := newShellService(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	defer timer.Stop()

	err := svc.executeFFmpegCommand(ctx, []string{"-c", "exec sleep 30"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
