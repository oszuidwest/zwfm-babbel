// Package audio provides audio processing services using FFmpeg.
package audio

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// Service handles audio processing operations using FFmpeg.
type Service struct {
	config *config.Config
}

// NewService creates a new audio processing service.
func NewService(cfg *config.Config) *Service {
	return &Service{config: cfg}
}

// ConvertToWAV converts uploaded audio files to standardized WAV format.
// channelCount: 1 for mono (stories), 2 for stereo (jingles)
func (s *Service) ConvertToWAV(ctx context.Context, inputPath, outputPath string, channelCount int) (string, float64, error) {
	// Convert to WAV 48kHz with specified channel count
	// #nosec G204 - FFmpegPath is from config, inputPath and outputPath are internally validated
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath,
		"-i", inputPath,
		"-ar", "48000",
		"-ac", fmt.Sprintf("%d", channelCount),
		"-acodec", "pcm_s16le",
		"-y", outputPath,
	)

	if err := cmd.Run(); err != nil {
		return "", 0, fmt.Errorf("ffmpeg failed to convert audio: %w", err)
	}

	duration, err := s.GetDuration(ctx, outputPath)
	if err != nil {
		return "", 0, err
	}

	return outputPath, duration, nil
}

// GetDuration retrieves the duration of an audio file in seconds using ffprobe.
func (s *Service) GetDuration(ctx context.Context, filePath string) (float64, error) {
	// #nosec G204 - ffprobe binary is trusted, filePath is internally validated
	cmd := exec.CommandContext(ctx, "ffprobe",
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
	if _, err := fmt.Sscanf(strings.TrimSpace(string(output)), "%f", &duration); err != nil {
		return 0, err
	}

	return duration, nil
}

// CreateBulletin generates a complete audio bulletin by combining multiple stories with station-specific jingles.
func (s *Service) CreateBulletin(ctx context.Context, station *models.Station, stories []models.Story, outputPath string) (string, error) {
	if len(stories) == 0 {
		return "", fmt.Errorf("no stories to create bulletin")
	}

	// Create temp directory for mixing
	tempDir := utils.GetTempBulletinDir(s.config, uuid.New().String())
	if err := os.MkdirAll(tempDir, 0750); err != nil {
		return "", err
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			// Ignore cleanup errors
			fmt.Printf("Warning: failed to cleanup temp directory %s: %v\n", tempDir, err)
		}
	}()

	// Build FFmpeg command - First mix all messages together, then overlay on bed
	args := []string{}
	filters := []string{}

	// Step 1: Add all story audio files
	for i, story := range stories {
		storyPath := utils.GetStoryPath(s.config, story.ID)
		args = append(args, "-i", storyPath)

		// Add padding after each story except the last one
		if station.PauseSeconds > 0 && i < len(stories)-1 {
			padMs := int(station.PauseSeconds * 1000)
			filters = append(filters, fmt.Sprintf("[%d:a]apad=pad_dur=%dms[padded%d]", i, padMs, i))
		} else {
			filters = append(filters, fmt.Sprintf("[%d:a]anull[padded%d]", i, i))
		}
	}

	// Step 2: Concatenate all stories into one timeline
	concatInputs := []string{}
	for i := range stories {
		concatInputs = append(concatInputs, fmt.Sprintf("[padded%d]", i))
	}
	concatFilter := fmt.Sprintf("%sconcat=n=%d:v=0:a=1[concat_messages]",
		strings.Join(concatInputs, ""), len(stories))
	filters = append(filters, concatFilter)

	// Step 2.5: Add delay to the message timeline based on the first story's mix point
	if len(stories) > 0 && stories[0].VoiceMixPoint > 0 {
		delayMs := int(stories[0].VoiceMixPoint * 1000)
		filters = append(filters, fmt.Sprintf("[concat_messages]adelay=%d[messages]", delayMs))
	} else {
		filters = append(filters, "[concat_messages]anull[messages]")
	}

	// Step 3: Add the bed/jingle (use the first story's voice as the bed)
	if len(stories) > 0 {
		// Use station-specific jingle
		jinglePath := utils.GetJinglePath(s.config, station.ID, *stories[0].VoiceID)

		if _, err := os.Stat(jinglePath); err == nil {
			args = append(args, "-i", jinglePath)

			// Calculate the correct jingle input index (number of stories)
			jingleIndex := len(stories)

			// Mix the complete message timeline with the bed, use first duration so bulletin ends when stories end
			filters = append(filters, fmt.Sprintf("[messages][%d:a]amix=inputs=2:duration=first:dropout_transition=0[out]", jingleIndex))
		} else {
			// No bed, just use the messages
			filters = append(filters, "[messages]anull[out]")
		}
	}

	// Final FFmpeg command
	args = append(args,
		"-filter_complex", strings.Join(filters, ";"),
		"-map", "[out]",
		"-y", outputPath)

	// #nosec G204 - FFmpegPath is from config, args are constructed internally
	cmd := exec.CommandContext(ctx, s.config.Audio.FFmpegPath, args...)

	// Print command for debugging
	fmt.Printf("DEBUG: Executing FFmpeg command: %s %s\n", s.config.Audio.FFmpegPath, strings.Join(args, " "))
	fmt.Printf("DEBUG: Filter complex: %s\n", strings.Join(filters, ";"))

	// Capture stderr for better error reporting
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start ffmpeg: %w", err)
	}

	stderrBytes, readErr := io.ReadAll(stderr)
	if readErr != nil {
		// Continue despite read error
		fmt.Printf("Failed to read stderr: %v\n", readErr)
	}

	if err := cmd.Wait(); err != nil {
		fmt.Printf("DEBUG: FFmpeg stderr: %s\n", string(stderrBytes))
		return "", fmt.Errorf("ffmpeg bulletin failed: %w. stderr: %s", err, string(stderrBytes))
	}

	return outputPath, nil
}
