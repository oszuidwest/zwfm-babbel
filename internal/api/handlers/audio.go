package handlers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// AudioConfig maps an audio endpoint to the database table and storage
// directory that contain its WAV file. All audio-bearing tables store the
// filename in the audio_file column keyed by id.
type AudioConfig struct {
	TableName  string
	FilePrefix string
	// FromOutput selects the bulletin output directory; the default is the
	// processed-audio directory. These match the directories the audio
	// pipeline writes to (BABBEL_OUTPUT_PATH / BABBEL_PROCESSED_PATH).
	FromOutput bool
}

// ServeAudio streams a stored WAV file for the route ID.
// Missing database records and missing files are both reported as 404 so
// callers do not need to distinguish metadata from storage state.
func (h *Handlers) ServeAudio(c *gin.Context, config AudioConfig) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	filePath, err := h.audioRepo.GetFilePath(c.Request.Context(), config.TableName, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			utils.ProblemNotFound(c, "Audio file")
			return
		}
		utils.ProblemInternalServer(c, "Failed to fetch record")
		return
	}

	baseDir := h.config.Audio.ProcessedPath
	if config.FromOutput {
		baseDir = h.config.Audio.OutputPath
	}
	audioPath := filepath.Join(baseDir, filePath)

	fileInfo, err := os.Stat(audioPath)
	if err != nil {
		if os.IsNotExist(err) {
			utils.ProblemNotFound(c, "Audio file")
		} else {
			utils.ProblemInternalServer(c, "Failed to access audio file")
		}
		return
	}
	if !validateAudioRange(c, fileInfo.Size()) {
		return
	}
	c.Header("Content-Type", "audio/wav")
	c.Header("Content-Disposition",
		fmt.Sprintf("inline; filename=\"%s_%d.wav\"", config.FilePrefix, id))

	c.File(audioPath)
}

func validateAudioRange(c *gin.Context, size int64) bool {
	if validByteRange(c.GetHeader("Range"), size) {
		return true
	}
	if size > 0 {
		c.Header("Content-Range", fmt.Sprintf("bytes */%d", size))
	}
	utils.ProblemCustom(
		c,
		"https://babbel.api/problems/range-not-satisfiable",
		"Range Not Satisfiable",
		416,
		"The requested byte range is invalid or does not overlap the audio file",
	)
	return false
}

// validByteRange mirrors net/http's byte-range validation so invalid ranges
// can use the API's Problem Details response before file serving begins.
//
//nolint:gocyclo // Keeping the range grammar linear makes its edge cases auditable.
func validByteRange(header string, size int64) bool {
	if header == "" {
		return true
	}
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return false
	}

	validRanges := 0
	noOverlap := false
	for value := range strings.SplitSeq(header[len(prefix):], ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		start, end, ok := strings.Cut(value, "-")
		if !ok {
			return false
		}
		start = strings.TrimSpace(start)
		end = strings.TrimSpace(end)
		if start == "" {
			if end == "" || strings.HasPrefix(end, "-") {
				return false
			}
			suffix, err := strconv.ParseInt(end, 10, 64)
			if err != nil || suffix < 0 {
				return false
			}
			validRanges++
			continue
		}

		first, err := strconv.ParseInt(start, 10, 64)
		if err != nil || first < 0 {
			return false
		}
		if first >= size {
			noOverlap = true
			continue
		}
		if end != "" {
			last, err := strconv.ParseInt(end, 10, 64)
			if err != nil || first > last {
				return false
			}
		}
		validRanges++
	}

	return size == 0 || !noOverlap || validRanges > 0
}

// UploadStoryAudio validates and converts an uploaded story file.
// The story must exist before temporary upload data is accepted.
func (h *Handlers) UploadStoryAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	exists, err := h.storySvc.Exists(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}
	if !exists {
		handleServiceError(c, apperrors.NotFoundWithID("Story", id), "Story")
		return
	}

	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "audio", fmt.Sprintf("story_%d", id))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "audio",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "audio file")()

	if err := h.storySvc.ProcessAudio(c.Request.Context(), id, tempPath); err != nil {
		handleServiceError(c, err, "Story")
		return
	}

	utils.CreatedWithMessage(c, "Audio uploaded successfully")
}

// UploadStationVoiceAudio validates and converts a station-voice jingle.
// The current relationship supplies the station and voice IDs used for the
// canonical output filename.
func (h *Handlers) UploadStationVoiceAudio(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	stationVoice, err := h.stationVoiceSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station-voice relationship")
		return
	}

	tempPath, cleanup, err := utils.ValidateAndSaveAudioFile(c, "jingle", fmt.Sprintf("station_%d_voice_%d", stationVoice.StationID, stationVoice.VoiceID))
	if err != nil {
		utils.ProblemValidationError(c, "Validation failed", []apperrors.ValidationError{{
			Field:   "jingle",
			Message: err.Error(),
		}})
		return
	}
	defer deferCleanup(cleanup, "jingle file")()

	if err := h.stationVoiceSvc.ProcessJingle(c.Request.Context(), stationVoice, tempPath); err != nil {
		handleServiceError(c, err, "Jingle processing")
		return
	}

	utils.CreatedWithMessage(c, "Jingle uploaded successfully")
}
