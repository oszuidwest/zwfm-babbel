package audio

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestConversionTimeoutStopsEachProcess(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell executables")
	}
	for _, phase := range []string{"probe", "measurement", "story conversion", "duration", "jingle conversion"} {
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			pidPath := filepath.Join(dir, "hung.pid")
			hang := "printf '%s' \"$$\" > '" + pidPath + "'\nexec sleep 30\n"
			probe := "printf '48000,1\\n'\n"
			measure := "printf '%s' '" + `{"input_i":"-16","input_tp":"-1","input_lra":"1","input_thresh":"-26","target_offset":"0"}` + "'\n"
			convert := ":\n"
			duration := "printf '1\\n'\n"
			switch phase {
			case "probe":
				probe = hang
			case "measurement":
				measure = hang
			case "story conversion", "jingle conversion":
				convert = hang
			case "duration":
				duration = hang
			}
			ffprobe := filepath.Join(dir, "ffprobe")
			ffmpeg := filepath.Join(dir, "ffmpeg")
			writeAudioTool(t, ffprobe, "case \"$*\" in *frame=*)\n"+probe+";; *)\n"+duration+";; esac\n")
			writeAudioTool(t, ffmpeg, "case \"$*\" in *print_format=json*)\n"+measure+";; *)\n"+convert+";; esac\n")
			svc := NewService(&config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe}}, nil)
			if svc.conversionTimeout != 3*time.Minute {
				t.Fatalf("default timeout = %s, want 3m", svc.conversionTimeout)
			}
			svc.conversionTimeout = 500 * time.Millisecond
			var err error
			if phase == "jingle conversion" {
				err = svc.ConvertJingleToWAV(t.Context(), "input", "output")
			} else {
				_, err = svc.ConvertStoryToWAV(t.Context(), "input", "output")
			}
			if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUndecodable) || t.Context().Err() != nil {
				t.Fatalf("conversion error = %v, caller error = %v; want local deadline", err, t.Context().Err())
			}
			assertAudioProcessStopped(t, pidPath)
		})
	}
}

func assertAudioProcessStopped(t *testing.T, pidPath string) {
	t.Helper()
	// #nosec G304 - PID marker is written by a test-owned tool in t.TempDir.
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatalf("hung process never started: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := process.Release(); err != nil {
			t.Error(err)
		}
	})
	if err := process.Signal(syscall.Signal(0)); err == nil {
		t.Fatalf("hung process %d survived the conversion deadline", pid)
	}
}

func TestConversionTimeoutIsSharedAcrossPasses(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("requires shell executables")
	}
	dir := t.TempDir()
	ffprobe, ffmpeg := filepath.Join(dir, "ffprobe"), filepath.Join(dir, "ffmpeg")
	writeAudioTool(t, ffprobe, "case \"$*\" in *frame=*) printf '48000,1\\n';; *) printf '1\\n';; esac\n")
	writeAudioTool(t, ffmpeg, "sleep 1.1\nprintf '%s' '"+`{"input_i":"-16","input_tp":"-1","input_lra":"1","input_thresh":"-26","target_offset":"0"}`+"'\n")
	svc := NewService(&config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe}}, nil)
	// Both passes fit individually, but not together. Leave ample scheduling
	// headroom for the first pass on a busy CI runner.
	svc.conversionTimeout = 2 * time.Second
	_, err := svc.ConvertStoryToWAV(t.Context(), "input", "output")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "convert audio") {
		t.Fatalf("conversion error = %v, want shared budget exhausted on the second pass", err)
	}
}

func writeAudioTool(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o700); err != nil { //nolint:gosec // Test executable.
		t.Fatal(err)
	}
}
