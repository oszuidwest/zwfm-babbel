// Package audio provides audio processing services using FFmpeg.
package audio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const (
	loudnessNormalizationFilter = "loudnorm=I=-16:TP=-1:LRA=11"
	truePeakMeasurementFilter   = loudnessNormalizationFilter + ":print_format=json"
	storyTruePeakTargetDBTP     = -1.0
)

type loudnormStats struct {
	InputTruePeak string `json:"input_tp"`
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

// ConvertToWAV converts uploaded audio files to standardized WAV format with
// EBU R128 loudness normalization.
func (s *Service) ConvertToWAV(
	ctx context.Context, inputPath, outputPath string, channelCount int,
) (string, float64, error) {
	return s.convertToWAV(ctx, inputPath, outputPath, channelCount, loudnessNormalizationFilter)
}

// ConvertStoryToWAV converts story audio to mono WAV and peak-normalizes it to -1 dBTP.
func (s *Service) ConvertStoryToWAV(ctx context.Context, inputPath, outputPath string) (string, float64, error) {
	gainDB, err := s.storyTruePeakGain(ctx, inputPath, int(Mono))
	if err != nil {
		return "", 0, err
	}

	return s.convertToWAV(ctx, inputPath, outputPath, int(Mono), storyNormalizationFilter(int(Mono), gainDB))
}

func (s *Service) convertToWAV(
	ctx context.Context, inputPath, outputPath string, channelCount int, audioFilter string,
) (string, float64, error) {
	args := []string{
		"-i", inputPath,
		"-af", audioFilter,
		"-ar", "48000",
		"-ac", strconv.Itoa(channelCount),
		"-acodec", "pcm_s16le",
		"-y", outputPath,
	}

	// #nosec G204 - FFmpegPath is from config, inputPath and outputPath are internally validated
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)

	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("ffmpeg failed to convert audio: %w", err)
	}

	duration, err := s.Duration(ctx, outputPath)
	if err != nil {
		return "", 0, err
	}

	return outputPath, duration, nil
}

func (s *Service) storyTruePeakGain(ctx context.Context, inputPath string, channelCount int) (float64, error) {
	truePeakDBTP, err := s.detectTruePeak(ctx, inputPath, channelCount)
	if err != nil {
		return 0, err
	}
	if math.IsInf(truePeakDBTP, -1) {
		return 0, nil
	}
	if math.IsInf(truePeakDBTP, 1) || math.IsNaN(truePeakDBTP) {
		return 0, fmt.Errorf("invalid true peak measurement: %v", truePeakDBTP)
	}

	return storyTruePeakTargetDBTP - truePeakDBTP, nil
}

func (s *Service) detectTruePeak(ctx context.Context, inputPath string, channelCount int) (float64, error) {
	filter := strings.Join([]string{
		loudnessNormalizationFilter,
		audioFormatFilter(channelCount),
		truePeakMeasurementFilter,
	}, ",")

	// #nosec G204 - FFmpegPath is from config and inputPath is internally validated
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath,
		"-i", inputPath,
		"-af", filter,
		"-f", "null",
		"-",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("ffmpeg failed to measure true peak: %w. output: %s", err, string(output))
	}

	truePeakDBTP, err := parseLoudnormInputTruePeak(string(output))
	if err != nil {
		s.alerts.Alert(ctx, notify.Event{
			Key:     "audio:loudnorm-parse",
			Summary: "FFmpeg loudnorm output could not be parsed",
			Details: err.Error(),
			Kind:    notify.KindContinuous,
		})
		return 0, err
	}
	s.alerts.Resolve(ctx, "audio:loudnorm-parse", "FFmpeg loudnorm parsing recovered", "Loudness measurements can be parsed again.")
	return truePeakDBTP, nil
}

func storyNormalizationFilter(channelCount int, gainDB float64) string {
	filters := []string{
		loudnessNormalizationFilter,
		audioFormatFilter(channelCount),
	}

	if math.Abs(gainDB) >= 0.001 {
		filters = append(filters, fmt.Sprintf("volume=%.6fdB", gainDB))
	}

	return strings.Join(filters, ",")
}

func audioFormatFilter(channelCount int) string {
	switch channelCount {
	case int(Mono):
		return "aformat=sample_rates=48000:channel_layouts=mono"
	case int(Stereo):
		return "aformat=sample_rates=48000:channel_layouts=stereo"
	default:
		return "aformat=sample_rates=48000"
	}
}

func parseLoudnormInputTruePeak(output string) (float64, error) {
	stats, err := parseLoudnormStats(output)
	if err != nil {
		return 0, err
	}
	return parseLoudnormNumber(stats.InputTruePeak)
}

func parseLoudnormStats(output string) (*loudnormStats, error) {
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end <= start {
		return nil, fmt.Errorf("failed to find loudnorm JSON stats in ffmpeg output")
	}

	var stats loudnormStats
	if err := json.Unmarshal([]byte(output[start:end+1]), &stats); err != nil {
		return nil, fmt.Errorf("failed to parse loudnorm JSON stats: %w", err)
	}
	if stats.InputTruePeak == "" {
		return nil, fmt.Errorf("loudnorm JSON stats missing input_tp")
	}

	return &stats, nil
}

func parseLoudnormNumber(value string) (float64, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "-inf":
		return math.Inf(-1), nil
	case "inf", "+inf":
		return math.Inf(1), nil
	}

	number, err := strconv.ParseFloat(normalized, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse loudnorm number %q: %w", value, err)
	}
	return number, nil
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
		return 0, fmt.Errorf("ffprobe failed: %w", err)
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
// independent of story order.
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

	args, filters := s.buildBulletinFFmpegCommand(ctx, station, stories, jingle, outputPath)

	return s.executeFFmpegCommand(ctx, args, filters, outputPath)
}

// buildBulletinFFmpegCommand constructs FFmpeg arguments and filters for bulletin creation.
func (s *Service) buildBulletinFFmpegCommand(
	ctx context.Context,
	station *models.Station,
	stories []repository.BulletinStoryData,
	jingle JingleContext,
	outputPath string,
) ([]string, []string) {
	args := []string{}
	filters := []string{}

	args, filters = s.addStoryInputsWithPadding(args, filters, station, stories)

	filters = s.addStoryConcat(filters, stories)

	filters = s.addMixPointDelay(filters, jingle.MixPoint)

	args, filters = s.addJingleMix(ctx, args, filters, station, jingle, len(stories))

	filters = append(filters, "[mixed]"+loudnessNormalizationFilter+"[out]")

	args = append(args,
		"-filter_complex", strings.Join(filters, ";"),
		"-map", "[out]",
		"-ac", "2",
		"-ar", "48000",
		"-y", outputPath)

	return args, filters
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
			Kind:    notify.KindImmediate,
		})
		filters = append(filters, "[messages]anull[mixed]")
		return args, filters
	}

	jinglePath := utils.JinglePath(s.config, station.ID, *jingle.VoiceID)

	if _, err := os.Stat(jinglePath); err != nil {
		if !os.IsNotExist(err) {
			logger.Warn("Failed to stat jingle file", "path", jinglePath, "error", err)
		} else {
			logger.Debug("Jingle file not found, generating bulletin without bed", "path", jinglePath)
		}
		s.alerts.Alert(ctx, notify.Event{
			Key:     alertKey,
			Summary: fmt.Sprintf("Jingle missing for station %d", station.ID),
			Details: fmt.Sprintf("Voice %d has no readable jingle at %s: %v. The bulletin was generated without a bed.", *jingle.VoiceID, jinglePath, err),
			Kind:    notify.KindImmediate,
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

// executeFFmpegCommand runs the FFmpeg command and handles error reporting.
func (s *Service) executeFFmpegCommand(ctx context.Context, args, filters []string, outputPath string) (string, error) {
	// #nosec G204 - FFmpegPath is from config, args are constructed internally
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)

	logger.Debug("Executing FFmpeg command", "binary", s.config.Audio.FFmpegPath, "args", strings.Join(args, " "))
	logger.Debug("FFmpeg filter complex", "filters", strings.Join(filters, ";"))

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
		return "", fmt.Errorf("ffmpeg bulletin failed: %w. stderr: %s", err, stderrStr)
	}

	return outputPath, nil
}
