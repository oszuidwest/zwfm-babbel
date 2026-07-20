package audio

import (
	"math"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestParseLoudnormInputTruePeak(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		output  string
		want    float64
		wantInf bool
		wantErr bool
	}{
		{
			name: "negative decibel value",
			output: `[Parsed_loudnorm_2 @ 0x123]
{
	"input_i" : "-16.05",
	"input_tp" : "-13.20",
	"input_lra" : "0.00",
	"input_thresh" : "-26.05"
}`,
			want: -13.2,
		},
		{
			name:    "silence",
			output:  `{"input_tp":"-inf"}`,
			wantInf: true,
		},
		{
			name:    "missing JSON stats",
			output:  "ffmpeg output without loudnorm stats",
			wantErr: true,
		},
		{
			name:    "missing input true peak",
			output:  `{"input_i":"-16.0"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseLoudnormInputTruePeak(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseLoudnormInputTruePeak error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLoudnormInputTruePeak error: %v", err)
			}
			if tt.wantInf {
				if !math.IsInf(got, -1) {
					t.Fatalf("parseLoudnormInputTruePeak = %v, want -Inf", got)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("parseLoudnormInputTruePeak = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStoryNormalizationFilter(t *testing.T) {
	t.Parallel()
	got := storyNormalizationFilter(int(Mono), 12.3456789)
	want := "loudnorm=I=-16:TP=-1:LRA=11,aformat=sample_rates=48000:channel_layouts=mono,volume=12.345679dB"
	if got != want {
		t.Fatalf("storyNormalizationFilter = %q, want %q", got, want)
	}
}

func TestService_ConvertStoryToWAVPeakNormalizesToMinusOneDBTP(t *testing.T) {
	t.Parallel()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "quiet-input.wav")
	outputPath := filepath.Join(tempDir, "story-output.wav")

	runFFmpeg(
		t,
		ffmpegPath,
		"-f", "lavfi",
		"-i", "sine=frequency=1000:duration=1",
		"-af", "volume=-24dB",
		"-ar", "44100",
		"-ac", "1",
		"-y", inputPath,
	)

	svc := NewService(&config.Config{
		Audio: config.AudioConfig{
			FFmpegPath:  ffmpegPath,
			FFprobePath: ffprobePath,
		},
	}, nil)

	convertedPath, duration, err := svc.ConvertStoryToWAV(t.Context(), inputPath, outputPath)
	if err != nil {
		t.Fatalf("ConvertStoryToWAV error: %v", err)
	}
	if convertedPath != outputPath {
		t.Fatalf("converted path = %q, want %q", convertedPath, outputPath)
	}
	if duration < 0.9 || duration > 1.1 {
		t.Fatalf("duration = %v, want around 1 second", duration)
	}

	truePeakDBTP := measureInputTruePeak(t, ffmpegPath, outputPath)
	if math.Abs(truePeakDBTP-storyTruePeakTargetDBTP) > 0.2 {
		t.Fatalf("true peak = %.1f dBTP, want %.1f dBTP", truePeakDBTP, storyTruePeakTargetDBTP)
	}
}

func runFFmpeg(t *testing.T, ffmpegPath string, args ...string) {
	t.Helper()
	// #nosec G204 - ffmpeg path is local; args are controlled test inputs
	cmd := exec.CommandContext(t.Context(), ffmpegPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg failed: %v. output: %s", err, string(output))
	}
}

func measureInputTruePeak(t *testing.T, ffmpegPath, inputPath string) float64 {
	t.Helper()
	// #nosec G204 - ffmpeg path is local; inputPath is test-generated
	cmd := exec.CommandContext(t.Context(), ffmpegPath,
		"-i", inputPath,
		"-af", truePeakMeasurementFilter,
		"-f", "null",
		"-",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg loudnorm measurement failed: %v. output: %s", err, string(output))
	}

	truePeakDBTP, err := parseLoudnormInputTruePeak(string(output))
	if err != nil {
		t.Fatalf("parseLoudnormInputTruePeak error: %v", err)
	}
	return truePeakDBTP
}
