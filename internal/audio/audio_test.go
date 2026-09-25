package audio

import (
	"math"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestParseLoudnormStats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		output     string
		want       loudnormStats
		wantSilent bool
		wantErr    bool
	}{
		{
			name: "measurement",
			output: `[Parsed_loudnorm_1 @ 0x123]
{
	"input_i" : "-19.76",
	"input_tp" : "-1.00",
	"input_lra" : "4.00",
	"input_thresh" : "-30.03",
	"output_i" : "-16.43",
	"normalization_type" : "dynamic",
	"target_offset" : "0.43"
}`,
			want: loudnormStats{Integrated: -19.76, TruePeak: -1, LRA: 4, Threshold: -30.03, TargetOffset: 0.43},
		},
		{
			name:       "silence",
			output:     `{"input_i":"-inf","input_tp":"-inf","input_lra":"0.00","input_thresh":"-70.00","target_offset":"inf"}`,
			wantSilent: true,
		},
		{
			name:    "missing JSON stats",
			output:  "ffmpeg output without loudnorm stats",
			wantErr: true,
		},
		{
			name:    "missing field",
			output:  `{"input_i":"-16.0","input_tp":"-1.0","input_lra":"4.0","input_thresh":"-26.0"}`,
			wantErr: true,
		},
		{
			name:    "malformed number",
			output:  `{"input_i":"loud","input_tp":"-1.0","input_lra":"4.0","input_thresh":"-26.0","target_offset":"0.0"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseLoudnormStats(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseLoudnormStats error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLoudnormStats error: %v", err)
			}
			if tt.wantSilent {
				if !got.silent() {
					t.Fatalf("parseLoudnormStats = %+v, want silent", got)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("parseLoudnormStats = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStoryNormalizationFilter(t *testing.T) {
	t.Parallel()
	got := storyNormalizationFilter(loudnormStats{Integrated: -19.76, TruePeak: -1, LRA: 4, Threshold: -30.03, TargetOffset: 0.43})
	want := "aformat=channel_layouts=mono," +
		"loudnorm=I=-16:TP=-1:LRA=11:measured_I=-19.76:measured_LRA=4.00:measured_TP=-1.00:measured_thresh=-30.03:offset=0.43:linear=true," +
		"aformat=sample_rates=48000:channel_layouts=mono"
	if got != want {
		t.Fatalf("storyNormalizationFilter = %q, want %q", got, want)
	}

	silent := storyNormalizationFilter(loudnormStats{Integrated: math.Inf(-1)})
	if silent != "aformat=sample_rates=48000:channel_layouts=mono" {
		t.Fatalf("storyNormalizationFilter(silent) = %q, want format-only filter", silent)
	}
}

func TestService_ConvertStoryToWAVNormalizesLoudness(t *testing.T) {
	t.Parallel()
	svc, ffmpegPath := newFFmpegService(t)

	for _, tt := range []struct {
		name   string
		volume string
	}{
		{name: "quiet input is raised", volume: "-24dB"},
		{name: "loud input is lowered", volume: "-3dB"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tempDir := t.TempDir()
			inputPath := filepath.Join(tempDir, "input.wav")
			outputPath := filepath.Join(tempDir, "story-output.wav")

			runFFmpeg(
				t,
				ffmpegPath,
				"-f", "lavfi",
				"-i", "sine=frequency=1000:duration=1",
				"-af", "volume="+tt.volume,
				"-ar", "44100",
				"-ac", "1",
				"-y", inputPath,
			)

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

			stats := measureLoudness(t, ffmpegPath, outputPath)
			if math.Abs(stats.Integrated+16) > 0.5 {
				t.Fatalf("integrated loudness = %.1f LUFS, want -16 LUFS", stats.Integrated)
			}
			if stats.TruePeak > -1+0.2 {
				t.Fatalf("true peak = %.1f dBTP, want at most -1 dBTP", stats.TruePeak)
			}
		})
	}
}

func TestService_ConvertStoryToWAVPassesSilenceThrough(t *testing.T) {
	t.Parallel()
	svc, ffmpegPath := newFFmpegService(t)

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "silence.wav")
	outputPath := filepath.Join(tempDir, "story-output.wav")
	runFFmpeg(t, ffmpegPath, "-f", "lavfi", "-i", "anullsrc=r=44100:cl=mono:d=1", "-y", inputPath)

	if _, _, err := svc.ConvertStoryToWAV(t.Context(), inputPath, outputPath); err != nil {
		t.Fatalf("ConvertStoryToWAV error: %v", err)
	}
	if !measureLoudness(t, ffmpegPath, outputPath).silent() {
		t.Fatal("converted silence is not silent")
	}
}

func TestService_ConvertJingleToWAVPreservesLevels(t *testing.T) {
	t.Parallel()
	svc, ffmpegPath := newFFmpegService(t)

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "dynamic-jingle.wav")
	outputPath := filepath.Join(tempDir, "jingle-output.wav")

	runFFmpeg(
		t,
		ffmpegPath,
		"-f", "lavfi",
		"-i", "sine=frequency=440:duration=2",
		"-af", "volume=-3dB,volume=-21dB:enable='gte(t,1)'",
		"-ar", "44100",
		"-ac", "2",
		"-y", inputPath,
	)

	if _, _, err := svc.ConvertJingleToWAV(t.Context(), inputPath, outputPath); err != nil {
		t.Fatalf("ConvertJingleToWAV error: %v", err)
	}

	for _, trimFilter := range []string{"atrim=end=0.9", "atrim=start=1.1"} {
		inputDBTP := measureLoudness(t, ffmpegPath, inputPath, trimFilter).TruePeak
		outputDBTP := measureLoudness(t, ffmpegPath, outputPath, trimFilter).TruePeak
		if math.Abs(outputDBTP-inputDBTP) > 0.2 {
			t.Fatalf("%s true peak changed from %.1f to %.1f dBTP", trimFilter, inputDBTP, outputDBTP)
		}
	}
}

// newFFmpegService returns a Service backed by the local ffmpeg and ffprobe
// binaries, or skips the test when either is missing.
func newFFmpegService(t *testing.T) (*Service, string) {
	t.Helper()
	ffmpegPath, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobePath, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	return NewService(&config.Config{
		Audio: config.AudioConfig{FFmpegPath: ffmpegPath, FFprobePath: ffprobePath},
	}, nil), ffmpegPath
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

func measureLoudness(t *testing.T, ffmpegPath, inputPath string, filters ...string) loudnormStats {
	t.Helper()
	// #nosec G204 - ffmpeg path is local; inputPath is test-generated
	cmd := exec.CommandContext(t.Context(), ffmpegPath,
		"-i", inputPath,
		"-af", strings.Join(append(filters, loudnessMeasurementFilter), ","),
		"-f", "null",
		"-",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ffmpeg loudnorm measurement failed: %v. output: %s", err, string(output))
	}

	stats, err := parseLoudnormStats(string(output))
	if err != nil {
		t.Fatalf("parseLoudnormStats error: %v", err)
	}
	return stats
}
