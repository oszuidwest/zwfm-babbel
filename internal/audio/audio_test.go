package audio

import (
	"math"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

func TestParseLoudnormStats(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		output  string
		want    loudnormStats
		wantErr bool
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
			name:   "silence",
			output: `{"input_i":"-inf","input_tp":"-inf","input_lra":"0.00","input_thresh":"-70.00","target_offset":"inf"}`,
			want:   loudnormStats{Integrated: math.Inf(-1), TruePeak: math.Inf(-1), Threshold: -70, TargetOffset: math.Inf(1)},
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
			if got != tt.want {
				t.Fatalf("parseLoudnormStats = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestStoryNormalizationFilter(t *testing.T) {
	t.Parallel()
	stats := loudnormStats{Integrated: -19.76, TruePeak: -1, LRA: 4, Threshold: -30.03, TargetOffset: 0.43}
	want := "aformat=channel_layouts=mono," +
		"loudnorm=I=-16:TP=-1:LRA=11:measured_I=-19.76:measured_LRA=4.00:measured_TP=-1.00:measured_thresh=-30.03:offset=0.43"
	if got := storyNormalizationFilter(stats); got != want {
		t.Fatalf("storyNormalizationFilter = %q, want %q", got, want)
	}

	short := loudnormStats{Integrated: math.Inf(-1), TruePeak: -1}
	if got := storyNormalizationFilter(short); got != monoDownmixFilter+","+loudnessNormalizationFilter {
		t.Fatalf("storyNormalizationFilter(short clip) = %q, want normalization without measurements", got)
	}
	if got := storyNormalizationFilter(loudnormStats{TruePeak: math.Inf(-1)}); got != "" {
		t.Fatalf("storyNormalizationFilter(silence) = %q, want no filter", got)
	}
}

func TestBulletinNormalizationFilter(t *testing.T) {
	t.Parallel()

	stats := loudnormStats{Integrated: -19.76, TruePeak: -1, LRA: 4, Threshold: -30.03, TargetOffset: 0.43}
	want := "loudnorm=I=-16:TP=-1:LRA=11:measured_I=-19.76:measured_LRA=4.00:measured_TP=-1.00:measured_thresh=-30.03:offset=0.43:linear=true"
	if got := bulletinNormalizationFilter(stats); got != want {
		t.Fatalf("bulletinNormalizationFilter = %q, want %q", got, want)
	}

	short := loudnormStats{Integrated: math.Inf(-1), TruePeak: -1}
	if got := bulletinNormalizationFilter(short); got != loudnessNormalizationFilter {
		t.Fatalf("bulletinNormalizationFilter(short mix) = %q, want dynamic normalization", got)
	}
	if got := bulletinNormalizationFilter(loudnormStats{TruePeak: math.Inf(-1)}); got != "anull" {
		t.Fatalf("bulletinNormalizationFilter(silence) = %q, want no-op filter", got)
	}
}

func TestBulletinArgs(t *testing.T) {
	t.Parallel()
	inputs := []string{"-i", "story_1.wav"}
	filters := []string{"[0:a]anull[messages]", "[messages]anull[mixed]"}

	got := strings.Join(bulletinArgs(inputs, filters, "anull"), " ")
	want := "-i story_1.wav -filter_complex [0:a]anull[messages];[messages]anull[mixed];[mixed]anull[out] -map [out]"
	if got != want {
		t.Fatalf("bulletinArgs = %q, want %q", got, want)
	}
}

func TestService_CreateBulletinNormalizesLoudness(t *testing.T) {
	t.Parallel()
	station := &models.Station{ID: 1, PauseSeconds: 0.5}
	voiceID := int64(1)
	stories := []repository.BulletinStoryData{
		{Story: models.Story{ID: 1}},
		{Story: models.Story{ID: 2}},
	}

	tests := []struct {
		name       string
		source     string
		jingle     JingleContext
		wantSilent bool
	}{
		{name: "voice over jingle", source: "sine=frequency=1000:duration=2", jingle: JingleContext{VoiceID: &voiceID, MixPoint: 1}},
		{name: "silence without jingle", source: "anullsrc=r=48000:cl=mono:d=2", wantSilent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc, ffmpegPath := newFFmpegService(t)
			svc.config.Audio.ProcessedPath = t.TempDir()

			for _, story := range stories {
				runFFmpeg(t, ffmpegPath, "-f", "lavfi", "-i", tt.source, "-af", "volume=5dB", "-ar", "48000", "-ac", "1", "-y", utils.StoryPath(svc.config, story.ID))
			}
			runFFmpeg(t, ffmpegPath, "-f", "lavfi", "-i", "sine=frequency=200:duration=10", "-af", "volume=-30dB", "-ar", "48000", "-ac", "2", "-y", utils.JinglePath(svc.config, station.ID, voiceID))
			outputPath := filepath.Join(t.TempDir(), "bulletin.wav")

			if _, err := svc.CreateBulletin(t.Context(), station, stories, tt.jingle, outputPath); err != nil {
				t.Fatalf("CreateBulletin error: %v", err)
			}

			stats := measureLoudness(t, ffmpegPath, outputPath)
			if tt.wantSilent {
				if !stats.silent() {
					t.Fatalf("silent bulletin measured %.1f LUFS", stats.Integrated)
				}
				return
			}
			if math.Abs(stats.Integrated+16) > 0.5 {
				t.Fatalf("integrated loudness = %.1f LUFS, want -16 LUFS", stats.Integrated)
			}
			if stats.TruePeak > -1+0.2 {
				t.Fatalf("true peak = %.1f dBTP, want at most -1 dBTP", stats.TruePeak)
			}
		})
	}
}

func TestService_ConvertStoryToWAVPreservesDynamics(t *testing.T) {
	t.Parallel()
	svc, ffmpegPath := newFFmpegService(t)

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.wav")
	outputPath := filepath.Join(tempDir, "story-output.wav")
	runFFmpeg(
		t,
		ffmpegPath,
		"-f", "lavfi",
		"-i", "sine=frequency=1000:duration=12",
		"-af", "volume=-10dB,volume=8dB:enable='gte(t,6)'",
		"-ar", "44100",
		"-ac", "1",
		"-y", inputPath,
	)

	inputStats := measureLoudness(t, ffmpegPath, inputPath)
	if inputStats.LRA == 0 {
		t.Fatal("test input LRA = 0, want a fixture that exercises linear normalization")
	}
	inputRange := levelRange(t, ffmpegPath, inputPath)

	_, duration, err := svc.ConvertStoryToWAV(t.Context(), inputPath, outputPath)
	if err != nil {
		t.Fatalf("ConvertStoryToWAV error: %v", err)
	}
	if duration < 11.9 || duration > 12.1 {
		t.Fatalf("duration = %v, want around 12 seconds", duration)
	}

	stats := measureLoudness(t, ffmpegPath, outputPath)
	if math.Abs(stats.Integrated+16) > 0.5 {
		t.Fatalf("integrated loudness = %.1f LUFS, want -16 LUFS", stats.Integrated)
	}
	if stats.TruePeak > -1+0.2 {
		t.Fatalf("true peak = %.1f dBTP, want at most -1 dBTP", stats.TruePeak)
	}
	if outputRange := levelRange(t, ffmpegPath, outputPath); math.Abs(outputRange-inputRange) > 0.2 {
		t.Fatalf("relative level range changed from %.1f to %.1f dB", inputRange, outputRange)
	}
}

func TestService_ConvertStoryToWAVLimitsShortClip(t *testing.T) {
	t.Parallel()
	svc, ffmpegPath := newFFmpegService(t)

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "short.wav")
	outputPath := filepath.Join(tempDir, "story-output.wav")
	runFFmpeg(
		t,
		ffmpegPath,
		"-f", "lavfi",
		"-i", "sine=frequency=1000:duration=0.1",
		"-af", "volume=21dB",
		"-c:a", "pcm_f32le",
		"-y", inputPath,
	)

	inputStats := measureLoudness(t, ffmpegPath, inputPath)
	if !math.IsInf(inputStats.Integrated, -1) || inputStats.TruePeak <= -1 {
		t.Fatalf("test input stats = %+v, want unavailable loudness and a true peak above -1 dBTP", inputStats)
	}
	if _, _, err := svc.ConvertStoryToWAV(t.Context(), inputPath, outputPath); err != nil {
		t.Fatalf("ConvertStoryToWAV error: %v", err)
	}
	if truePeak := measureLoudness(t, ffmpegPath, outputPath).TruePeak; truePeak > -1+0.2 {
		t.Fatalf("true peak = %.1f dBTP, want at most -1 dBTP", truePeak)
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

func levelRange(t *testing.T, ffmpegPath, inputPath string) float64 {
	t.Helper()
	quiet := measureLoudness(t, ffmpegPath, inputPath, "atrim=end=5.5").TruePeak
	loud := measureLoudness(t, ffmpegPath, inputPath, "atrim=start=6.5").TruePeak
	return loud - quiet
}
