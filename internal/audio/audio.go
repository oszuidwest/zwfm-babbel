// Package audio provides audio processing services using FFmpeg.
package audio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// commandError preserves context errors so callers can recognize canceled commands.
func commandError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return errors.Join(ctxErr, err)
	}
	return err
}

const (
	loudnessNormalizationFilter = "loudnorm=I=-16:TP=-1:LRA=11"
	loudnessMeasurementFilter   = loudnessNormalizationFilter + ":print_format=json"
	// minStoryLoudnessLUFS is the minimum accepted story loudness.
	minStoryLoudnessLUFS = -50
	// monoDownmixFilter keeps both loudnorm passes on the same mono signal.
	monoDownmixFilter = "aformat=channel_layouts=mono"
)

// ErrSilent indicates story audio below the usable loudness floor.
var ErrSilent = errors.New("audio is silent or too quiet")

// loudnormStats carries first-pass measurements into the linear second pass.
type loudnormStats struct {
	Integrated   float64
	TruePeak     float64
	LRA          float64
	Threshold    float64
	TargetOffset float64
}

// silent reports whether loudnorm found no measurable peak.
func (l loudnormStats) silent() bool {
	return math.IsInf(l.TruePeak, -1)
}

// tooQuiet reports whether story audio is below the loudness floor.
// Below 400 ms or the -70 LUFS gate, integrated loudness is unavailable;
// the same threshold applies to true peak in dBTP.
func (l loudnormStats) tooQuiet() bool {
	if math.IsInf(l.Integrated, -1) {
		return l.TruePeak < minStoryLoudnessLUFS
	}
	return l.Integrated < minStoryLoudnessLUFS
}

// JingleContext keeps the jingle and mix point stable across story shuffling.
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
	return &Service{config: cfg, alerts: notify.OrDiscard(alerts)}
}

// ConvertJingleToWAV converts a jingle to stereo WAV without changing its level.
// It returns the duration in seconds.
func (s *Service) ConvertJingleToWAV(ctx context.Context, inputPath, outputPath string) (float64, error) {
	return s.convertToWAV(ctx, inputPath, outputPath, Stereo, "")
}

// ConvertStoryToWAV converts story audio to mono WAV, targeting -16 LUFS with
// a -1 dBTP ceiling, preserving dynamics when possible.
// It returns the duration in seconds.
//
// It returns [ErrSilent] without writing outputPath when the input is silent
// or below -50 LUFS (-50 dBTP when integrated loudness is unavailable).
func (s *Service) ConvertStoryToWAV(ctx context.Context, inputPath, outputPath string) (float64, error) {
	stats, err := s.measureLoudness(ctx, inputPath)
	if err != nil {
		return 0, err
	}

	if stats.tooQuiet() {
		logger.Warn("Rejected silent or near-silent story audio",
			"path", inputPath,
			"input_i", fmt.Sprintf("%.2f", stats.Integrated),
			"input_tp", fmt.Sprintf("%.2f", stats.TruePeak),
			"input_lra", fmt.Sprintf("%.2f", stats.LRA),
			"input_thresh", fmt.Sprintf("%.2f", stats.Threshold),
		)
		return 0, ErrSilent
	}

	return s.convertToWAV(ctx, inputPath, outputPath, Mono, storyNormalizationFilter(stats))
}

func (s *Service) convertToWAV(
	ctx context.Context, inputPath, outputPath string, channels ChannelCount, audioFilter string,
) (float64, error) {
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
		return 0, fmt.Errorf("ffmpeg failed to convert audio: %w", commandError(ctx, err))
	}

	return s.Duration(ctx, outputPath)
}

func (s *Service) measureLoudness(ctx context.Context, inputPath string) (loudnormStats, error) {
	return s.measureLoudnessWithArgs(ctx,
		"-i", inputPath,
		"-af", monoDownmixFilter+","+loudnessMeasurementFilter,
	)
}

// measureLoudnessWithArgs measures loudness using caller-supplied FFmpeg arguments.
func (s *Service) measureLoudnessWithArgs(ctx context.Context, args ...string) (loudnormStats, error) {
	// #nosec G204 - FFmpegPath is from config and args are constructed internally
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

// storyNormalizationFilter uses dynamic mode when integrated loudness is unavailable.
func storyNormalizationFilter(stats loudnormStats) string {
	filter := monoDownmixFilter + "," + loudnessNormalizationFilter
	if math.IsInf(stats.Integrated, -1) {
		return filter
	}

	return filter + fmt.Sprintf(":measured_I=%.2f:measured_LRA=%.2f:measured_TP=%.2f:measured_thresh=%.2f:offset=%.2f",
		stats.Integrated, stats.LRA, stats.TruePeak, stats.Threshold, stats.TargetOffset)
}

// bulletinNormalizationFilter normalizes the stereo mix, bypassing silence.
// Without integrated loudness, dynamic mode limits true peak.
func bulletinNormalizationFilter(stats loudnormStats) string {
	if stats.silent() {
		return "anull"
	}
	if math.IsInf(stats.Integrated, -1) {
		return loudnessNormalizationFilter
	}

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

	// ParseFloat accepts loudnorm's infinity values and rejects missing fields.
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

// CreateBulletin mixes stories with the selected jingle into outputPath.
// Two-pass normalization preserves the stereo mix's voice-to-bed balance.
func (s *Service) CreateBulletin(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle JingleContext,
	outputPath string,
) error {
	if len(stories) == 0 {
		return fmt.Errorf("no stories to create bulletin")
	}

	inputs, filters := s.buildBulletinMix(ctx, station, stories, jingle)

	stats, err := s.measureLoudnessWithArgs(ctx, bulletinArgs(inputs, filters, loudnessMeasurementFilter)...)
	if err != nil {
		return err
	}

	args := append(bulletinArgs(inputs, filters, bulletinNormalizationFilter(stats)),
		"-ac", strconv.Itoa(int(Stereo)),
		"-ar", "48000",
		"-y", outputPath)

	return s.executeFFmpegCommand(ctx, args)
}

// buildBulletinMix constructs the FFmpeg inputs and filter graph that produce
// the unnormalized [mixed] stream: stories in playback order with the
// configured pauses, concatenated and delayed to a positive mix point.
func (s *Service) buildBulletinMix(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle JingleContext,
) ([]string, []string) {
	var inputs, filters []string
	var concatInputs strings.Builder
	for i, story := range stories {
		inputs = append(inputs, "-i", utils.StoryPath(s.config, story.ID))

		if station.PauseSeconds > 0 && i < len(stories)-1 {
			padMs := int(station.PauseSeconds * 1000)
			filters = append(filters, fmt.Sprintf("[%d:a]apad=pad_dur=%dms[padded%d]", i, padMs, i))
		} else {
			filters = append(filters, fmt.Sprintf("[%d:a]anull[padded%d]", i, i))
		}
		fmt.Fprintf(&concatInputs, "[padded%d]", i)
	}
	filters = append(filters, fmt.Sprintf("%sconcat=n=%d:v=0:a=1[concat_messages]", concatInputs.String(), len(stories)))

	if jingle.MixPoint > 0 {
		filters = append(filters, fmt.Sprintf("[concat_messages]adelay=%d[messages]", int(jingle.MixPoint*1000)))
	} else {
		filters = append(filters, "[concat_messages]anull[messages]")
	}

	return s.addJingleMix(ctx, inputs, filters, station, jingle, len(stories))
}

// bulletinArgs completes the mix graph with outFilter on [mixed] so both
// loudnorm passes process exactly the same input graph.
func bulletinArgs(inputs, filters []string, outFilter string) []string {
	graph := strings.Join(filters, ";") + ";[mixed]" + outFilter + "[out]"
	return slices.Concat(inputs, []string{"-filter_complex", graph, "-map", "[out]"})
}

// addJingleMix adds the optional bed, reports availability, and labels the
// result for final loudness normalization.
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
		if os.IsNotExist(err) {
			logger.Debug("Jingle file not found, generating bulletin without bed", "path", jinglePath)
		} else {
			logger.Warn("Jingle file is not usable", "path", jinglePath, "error", err)
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
		// Upmix only the stories to preserve the jingle's stereo image.
		filters = append(filters,
			"[messages]aformat=channel_layouts=stereo[messages_stereo]",
			fmt.Sprintf("[messages_stereo][%d:a]amix=inputs=2:duration=first:dropout_transition=0[mixed]", storyCount))
	}

	return args, filters
}

// validateJingleFile checks that path is a readable regular file.
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

// executeFFmpegCommand captures stderr so failures retain FFmpeg diagnostics.
func (s *Service) executeFFmpegCommand(ctx context.Context, args []string) error {
	// #nosec G204 - FFmpegPath is from config, args are constructed internally
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	logger.Debug("Executing FFmpeg command", "binary", s.config.Audio.FFmpegPath, "args", strings.Join(args, " "))

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ffmpeg: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		logger.Debug("FFmpeg stderr output", "stderr", stderr.String())
		return fmt.Errorf("ffmpeg bulletin failed: %w. stderr: %s", commandError(ctx, err), stderr.String())
	}

	return nil
}
