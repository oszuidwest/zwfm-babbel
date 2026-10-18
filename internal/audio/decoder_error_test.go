package audio

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestFFmpegErrorPreservesOperationalFailures(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell executable")
	}
	for _, tt := range []struct {
		name        string
		code        int
		contextErr  error
		undecodable bool
	}{
		{name: "decoder error rate", code: 69, undecodable: true},
		{name: "generic processing error", code: 1},
		{name: "tool failure", code: 2},
		{name: "cancelled decoder", code: 69, contextErr: context.Canceled},
		{name: "expired decoder", code: 69, contextErr: context.DeadlineExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// #nosec G204 -- exit codes are controlled integer literals in this table.
			err := exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit "+strconv.Itoa(tt.code)).Run()
			ctx := t.Context()
			switch {
			case errors.Is(tt.contextErr, context.Canceled):
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case errors.Is(tt.contextErr, context.DeadlineExceeded):
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
			}
			got := ffmpegError(ctx, err)
			if errors.Is(got, ErrUndecodable) != tt.undecodable || !errors.Is(got, err) || (tt.contextErr != nil && !errors.Is(got, tt.contextErr)) {
				t.Fatalf("ffmpegError = %v, want undecodable=%t, cause=%v, context=%v", got, tt.undecodable, err, tt.contextErr)
			}
		})
	}
}

func TestService_ClassifiesDecoderFailureInBothPasses(t *testing.T) {
	t.Parallel()
	ffmpeg, _ := testutil.DecoderErrorTools(t)
	svc := NewService(&config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg}}, nil)
	t.Run("measurement", func(t *testing.T) {
		_, err := svc.measureLoudness(t.Context(), "input.opus")
		if !errors.Is(err, ErrUndecodable) {
			t.Fatalf("measurement = %v, want ErrUndecodable", err)
		}
	})
	t.Run("conversion", func(t *testing.T) {
		err := svc.convertToWAV(t.Context(), "input.opus", "output.wav", 1, "")
		if !errors.Is(err, ErrUndecodable) {
			t.Fatalf("conversion = %v, want ErrUndecodable", err)
		}
	})
}
