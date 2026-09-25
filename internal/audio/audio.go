// Package audio provides audio processing services using FFmpeg.
package audio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// commandError surfaces context cancellation hidden behind the process error:
// exec returns the kill signal ("signal: killed"), not ctx.Err(), when the
// context ends a run, and callers classify shutdown by matching ctx errors.
func commandError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err)
	}
	return err
}

const (
	loudnessNormalizationFilter = "loudnorm=I=-16:TP=-1:LRA=11"
	loudnessMeasurementFilter   = loudnessNormalizationFilter + ":print_format=json"
	// monoDownmixFilter runs ahead of loudnorm in both story passes so the
	// second pass applies its gain to the signal the first pass measured.
	monoDownmixFilter = "aformat=channel_layouts=mono"
)

// loudnormStats holds the first-pass measurements that loudnorm prints as
// JSON. The second pass feeds them back so loudnorm can apply a linear gain.
type loudnormStats struct {
	Integrated   float64
	TruePeak     float64
	LRA          float64
	Threshold    float64
	TargetOffset float64
}

// silent reports whether loudnorm measured no signal at all.
func (l loudnormStats) silent() bool {
	return math.IsInf(l.Integrated, -1)
}

// JingleContext holds jingle selection data captured before story order randomization.
// This ensures the jingle and mix point remain stable regardless of shuffle order.
type JingleContext struct {
	VoiceID  *int64
	MixPoint float64
}

// Service runs FFmpeg operations using configured storage paths and binaries.
type Service struct {
	config *config.Config
	alerts notify.Alerter
}

// NewService returns an audio service using cfg.
func NewService(cfg *config.Config, alerts notify.Alerter) *Service {
	alerts = notify.OrDiscard(alerts)
	return &Service{config: cfg, alerts: alerts}
}

// ConvertJingleToWAV converts a jingle to the standard stereo WAV format
// without changing its intended level balance. The completed bulletin is
// normalized after the jingle and stories are mixed.
func (s *Service) ConvertJingleToWAV(ctx context.Context, inputPath, outputPath string) (string, float64, error) {
	return s.convertToWAV(ctx, inputPath, outputPath, Stereo, "")
}

// ConvertStoryToWAV converts story audio to mono WAV at -16 LUFS with a
// -1 dBTP ceiling. It runs loudnorm in two passes: the first measures the
// mono downmix, the second applies a linear gain from those measurements so
// the voice keeps its dynamics. Loudnorm itself falls back to dynamic mode
// when a linear gain would push the true peak above the ceiling.
func (s *Service) ConvertStoryToWAV(ctx context.Context, inputPath, outputPath string) (string, float64, error) {
	stats, err := s.measureLoudness(ctx, "-i", inputPath, "-af", monoDownmixFilter+","+loudnessMeasurementFilter)
	if err != nil {
		return "", 0, err
	}

	return s.convertToWAV(ctx, inputPath, outputPath, Mono, storyNormalizationFilter(stats))
}

func (s *Service) convertToWAV(
	ctx context.Context, inputPath, outputPath string, channels ChannelCount, audioFilter string,
) (string, float64, error) {
	args := []string{"-i", inputPath}
	if audioFilter != "" {
		args = append(args, "-af", audioFilter)
	}
	args = append(args,
		"-ar", "48000",
		"-ac", strconv.Itoa(int(channels)),
		"-acodec", "pcm_s16le",
		"-y", outputPath,
	)

	// #nosec G204 - FFmpegPath is from config, inputPath and outputPath are internally validated
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)

	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("ffmpeg failed to convert audio: %w", commandError(ctx, err))
	}

	duration, err := s.Duration(ctx, outputPath)
	if err != nil {
		return "", 0, err
	}

	return outputPath, duration, nil
}

// measureLoudness runs the first loudnorm pass described by args, which must
// route the audio through loudnessMeasurementFilter, and parses the stats
// that loudnorm prints.
func (s *Service) measureLoudness(ctx context.Context, args ...string) (loudnormStats, error) {
	// #nosec G204 - FFmpegPath is from config, args are constructed internally
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, append(args, "-f", "null", "-")...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return loudnormStats{}, fmt.Errorf("ffmpeg failed to measure loudness: %w. output: %s", commandError(ctx, err), string(output))
	}

	stats, err := parseLoudnormStats(string(output))
	if err != nil {
		s.alerts.Alert(ctx, notify.Event{
			Key:               "audio:loudnorm-parse",
			Summary:           "FFmpeg loudnorm output could not be parsed",
			Details:           err.Error(),
			RequiresThreshold: true,
		})
		return loudnormStats{}, err
	}
	s.alerts.Resolve(ctx, "audio:loudnorm-parse", "FFmpeg loudnorm parsing recovered", "Loudness measurements can be parsed again.")
	return stats, nil
}

// storyNormalizationFilter builds the second-pass filter chain. Silence has
// nothing to normalize and loudnorm rejects -inf measurements, so it takes
// the same filter-free route as jingles.
func storyNormalizationFilter(stats loudnormStats) string {
	if stats.silent() {
		return ""
	}

	return monoDownmixFilter + "," + linearLoudnormFilter(stats)
}

// bulletinNormalizationFilter builds the second pass over the [mixed] bulletin.
func bulletinNormalizationFilter(stats loudnormStats) string {
	if stats.silent() {
		return "anull"
	}

	return linearLoudnormFilter(stats)
}

// linearLoudnormFilter feeds the first-pass measurements back to loudnorm so
// it applies a linear gain instead of riding the level dynamically.
func linearLoudnormFilter(stats loudnormStats) string {
	return fmt.Sprintf("%s:measured_I=%.2f:measured_LRA=%.2f:measured_TP=%.2f:measured_thresh=%.2f:offset=%.2f:linear=true",
		loudnessNormalizationFilter, stats.Integrated, stats.LRA, stats.TruePeak, stats.Threshold, stats.TargetOffset)
}

func parseLoudnormStats(output string) (loudnormStats, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end <= start {
		return loudnormStats{}, fmt.Errorf("failed to find loudnorm JSON stats in ffmpeg output")
	}

	var raw map[string]string
	if err := json.Unmarshal([]byte(output[start:end+1]), &raw); err != nil {
		return loudnormStats{}, fmt.Errorf("failed to parse loudnorm JSON stats: %w", err)
	}

	// strconv.ParseFloat accepts the "inf" and "-inf" that loudnorm prints for
	// silence, and rejects the empty string a missing key yields.
	var stats loudnormStats
	for _, field := range []struct {
		key string
		dst *float64
	}{
		{"input_i", &stats.Integrated},
		{"input_tp", &stats.TruePeak},
		{"input_lra", &stats.LRA},
		{"input_thresh", &stats.Threshold},
		{"target_offset", &stats.TargetOffset},
	} {
		value, err := strconv.ParseFloat(raw[field.key], 64)
		if err != nil {
			return loudnormStats{}, fmt.Errorf("loudnorm JSON stat %s=%q: %w", field.key, raw[field.key], err)
		}
		*field.dst = value
	}

	return stats, nil
}

// Duration retrieves the duration of an audio file in seconds using ffprobe.
func (s *Service) Duration(ctx context.Context, filePath string) (float64, error) {
	// #nosec G204 - ffprobe binary is from config, filePath is internally validated
	cmd := exec.CommandContext(ctx, s.config.Audio.FFprobePath,
		"-i", filePath,
		"-show_entries", "format=duration",
		"-v", "quiet",
		"-of", "csv=p=0",
	)

	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("ffprobe failed: %w", commandError(ctx, err))
	}

	var duration float64
	outputStr := strings.TrimSpace(string(output))
	if _, err := fmt.Sscanf(outputStr, "%f", &duration); err != nil {
		return 0, fmt.Errorf("failed to parse duration from output %q: %w", outputStr, err)
	}

	return duration, nil
}

// CreateBulletin generates a complete audio bulletin by combining multiple
// stories with station-specific jingles.
// The jingle parameter determines which jingle and mix point to use,
// independent of story order. The mix is normalized in two loudnorm passes:
// the first measures the stereo mix, the second applies a linear gain from
// those measurements so the balance between jingle and voice survives.
func (s *Service) CreateBulletin(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle JingleContext,
	outputPath string,
) (string, error) {
	if len(stories) == 0 {
		return "", fmt.Errorf("no stories to create bulletin")
	}

	inputs, filters := s.buildBulletinMix(ctx, station, stories, jingle)

	stats, err := s.measureLoudness(ctx, bulletinArgs(inputs, filters, loudnessMeasurementFilter)...)
	if err != nil {
		return "", err
	}

	args := append(bulletinArgs(inputs, filters, bulletinNormalizationFilter(stats)),
		"-ac", "2",
		"-ar", "48000",
		"-y", outputPath)

	return s.executeFFmpegCommand(ctx, args, outputPath)
}

// buildBulletinMix constructs the FFmpeg inputs and the filter graph that
// mixes the stories and jingle into the [mixed] stream.
func (s *Service) buildBulletinMix(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle JingleContext,
) ([]string, []string) {
	inputs := []string{}
	filters := []string{}

	inputs, filters = s.addStoryInputsWithPadding(inputs, filters, station, stories)

	filters = s.addStoryConcat(filters, stories)

	filters = s.addMixPointDelay(filters, jingle.MixPoint)

	return s.addJingleMix(ctx, inputs, filters, station, jingle, len(stories))
}

// bulletinArgs completes the mix graph with outFilter on [mixed] and maps
// the result, so both loudnorm passes run over the same graph.
func bulletinArgs(inputs, filters []string, outFilter string) []string {
	graph := strings.Join(append(slices.Clone(filters), "[mixed]"+outFilter+"[out]"), ";")
	return append(slices.Clone(inputs), "-filter_complex", graph, "-map", "[out]")
}

// addStoryInputsWithPadding adds story audio files as inputs with appropriate padding.
func (s *Service) addStoryInputsWithPadding(
	args, filters []string,
	station *models.Station,
	stories []repository.BulletinStoryData,
) ([]string, []string) {
	for i, story := range stories {
		storyPath := utils.StoryPath(s.config, story.ID)
		args = append(args, "-i", storyPath)

		if station.PauseSeconds > 0 && i < len(stories)-1 {
			padMs := int(station.PauseSeconds * 1000)
			filters = append(filters, fmt.Sprintf("[%d:a]apad=pad_dur=%dms[padded%d]", i, padMs, i))
		} else {
			filters = append(filters, fmt.Sprintf("[%d:a]anull[padded%d]", i, i))
		}
	}
	return args, filters
}

// addStoryConcat creates a filter to concatenate all stories into one timeline.
func (s *Service) addStoryConcat(filters []string, stories []repository.BulletinStoryData) []string {
	concatInputs := []string{}
	for i := range stories {
		concatInputs = append(concatInputs, fmt.Sprintf("[padded%d]", i))
	}
	concatFilter := fmt.Sprintf("%sconcat=n=%d:v=0:a=1[concat_messages]",
		strings.Join(concatInputs, ""), len(stories))
	return append(filters, concatFilter)
}

// addMixPointDelay adds delay to the message timeline based on the jingle's mix point.
func (s *Service) addMixPointDelay(filters []string, mixPoint float64) []string {
	if mixPoint > 0 {
		delayMs := int(mixPoint * 1000)
		return append(filters, fmt.Sprintf("[concat_messages]adelay=%d[messages]", delayMs))
	}
	return append(filters, "[concat_messages]anull[messages]")
}

// addJingleMix adds the bed/jingle when present, reports the availability
// decision, and writes the final stream to [mixed] for loudness normalization.
func (s *Service) addJingleMix(
	ctx context.Context,
	args, filters []string,
	station *models.Station,
	jingle JingleContext,
	storyCount int,
) ([]string, []string) {
	alertKey := fmt.Sprintf("bulletin:missing-jingle:station:%d", station.ID)
	if jingle.VoiceID == nil {
		logger.Debug("No voice ID in jingle context, generating bulletin without bed")
		s.alerts.Alert(ctx, notify.Event{
			Key:     alertKey,
			Summary: fmt.Sprintf("Bulletin for station %d has no jingle voice", station.ID),
			Details: "The bulletin was generated without a jingle because its selected story has no voice.",
		})
		filters = append(filters, "[messages]anull[mixed]")
		return args, filters
	}

	jinglePath := utils.JinglePath(s.config, station.ID, *jingle.VoiceID)

	if err := validateJingleFile(jinglePath); err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("Jingle file is not usable", "path", jinglePath, "error", err)
		} else {
			logger.Debug("Jingle file not found, generating bulletin without bed", "path", jinglePath)
		}
		s.alerts.Alert(ctx, notify.Event{
			Key:     alertKey,
			Summary: fmt.Sprintf("Jingle missing for station %d", station.ID),
			Details: fmt.Sprintf("Voice %d has no readable jingle at %s: %v. The bulletin was generated without a bed.", *jingle.VoiceID, jinglePath, err),
		})
		filters = append(filters, "[messages]anull[mixed]")
	} else {
		s.alerts.Resolve(ctx, alertKey, fmt.Sprintf("Jingle available again for station %d", station.ID),
			fmt.Sprintf("The jingle for voice %d is readable again.", *jingle.VoiceID))
		args = append(args, "-i", jinglePath)
		jingleIndex := storyCount
		// Convert mono messages to stereo before mixing to preserve the jingle's stereo image.
		filters = append(filters, "[messages]aformat=channel_layouts=stereo[messages_stereo]")
		filters = append(filters,
			fmt.Sprintf("[messages_stereo][%d:a]amix=inputs=2:duration=first:dropout_transition=0[mixed]", jingleIndex))
	}

	return args, filters
}

// validateJingleFile ensures the path is a readable regular file before an
// availability incident is resolved and FFmpeg receives it as an input.
func validateJingleFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("jingle path is not a regular file")
	}

	file, err := os.Open(path) //nolint:gosec // Path is built internally from the configured storage root and numeric IDs.
	if err != nil {
		return fmt.Errorf("open jingle file: %w", err)
	}
	openedInfo, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil {
		return fmt.Errorf("stat opened jingle file: %w", statErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close jingle file: %w", closeErr)
	}
	if !openedInfo.Mode().IsRegular() {
		return fmt.Errorf("opened jingle path is not a regular file")
	}
	return nil
}

// executeFFmpegCommand runs the FFmpeg command and handles error reporting.
func (s *Service) executeFFmpegCommand(ctx context.Context, args []string, outputPath string) (string, error) {
	// #nosec G204 - FFmpegPath is from config, args are constructed internally
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)

	logger.Debug("Executing FFmpeg command", "binary", s.config.Audio.FFmpegPath, "args", strings.Join(args, " "))

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start ffmpeg: %w", err)
	}

	stderrBytes, readErr := io.ReadAll(stderr)
	if readErr != nil {
		// Continue despite read errors.
		logger.Warn("Failed to read FFmpeg stderr", "error", readErr)
	}

	if err := cmd.Wait(); err != nil {
		logger.Debug("FFmpeg stderr output", "stderr", string(stderrBytes))
		stderrStr := string(stderrBytes)
		if readErr != nil {
			stderrStr = fmt.Sprintf("(stderr read failed: %v)", readErr)
		}
		return "", fmt.Errorf("ffmpeg bulletin failed: %w. stderr: %s", commandError(ctx, err), stderrStr)
	}

	return outputPath, nil
}
