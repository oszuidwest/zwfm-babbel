package handlers

import (
	"fmt"
	"mime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// GenerateBulletin queues durable asynchronous bulletin generation.
func (h *Handlers) GenerateBulletin(c *gin.Context) {
	if !acceptsJSON(strings.Join(c.Request.Header.Values("Accept"), ",")) {
		utils.ProblemNotAcceptable(c, "Bulletin generation returns application/json; fetch audio from the bulletin audio URL")
		return
	}

	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req struct {
		Date string `json:"date"`
	}
	if !utils.BindOptionalJSON(c, &req) {
		return
	}

	targetDate, err := services.ParseTargetDate(req.Date)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	if !h.requireStation(c, stationID) {
		return
	}

	job, err := h.bulletinJobSvc.Enqueue(c.Request.Context(), stationID, targetDate)
	if err != nil {
		handleServiceError(c, err, "Bulletin job")
		return
	}

	utils.AcceptedWithLocation(c, job.ID, "/api/v1/bulletin-jobs", job)
}

// GetBulletinJob returns the current state of an asynchronous generation job.
func (h *Handlers) GetBulletinJob(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}
	job, err := h.bulletinJobSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Bulletin job")
		return
	}
	utils.Success(c, job)
}

func acceptsJSON(header string) bool {
	if header == "" {
		return true
	}

	bestSpecificity := -1
	acceptable := false
	for mediaRange := range strings.SplitSeq(header, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(mediaRange))
		if err != nil {
			continue
		}

		specificity := slices.Index([]string{"*/*", "application/*", gin.MIMEJSON}, mediaType)
		if specificity < 0 {
			continue
		}

		quality := 1.0
		if value, ok := params["q"]; ok {
			quality, ok = parseQuality(value)
			if !ok {
				continue
			}
		}

		if mediaType == gin.MIMEJSON && quality > 0 {
			return true
		}
		if specificity < bestSpecificity {
			continue
		}
		if specificity > bestSpecificity {
			bestSpecificity = specificity
			acceptable = false
		}
		acceptable = acceptable || quality > 0
	}

	return acceptable
}

func parseQuality(value string) (float64, bool) {
	switch value {
	case "0":
		return 0, true
	case "1":
		return 1, true
	}

	integer, fraction, found := strings.Cut(value, ".")
	if !found || len(fraction) > 3 || (integer != "0" && integer != "1") {
		return 0, false
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' || (integer == "1" && digit != '0') {
			return 0, false
		}
	}

	quality, err := strconv.ParseFloat(value, 64)
	return quality, err == nil
}

// requireStation returns false after writing a response when the station
// lookup fails or the station does not exist.
func (h *Handlers) requireStation(c *gin.Context, stationID int64) bool {
	exists, err := h.stationSvc.Exists(c.Request.Context(), stationID)
	if err != nil {
		handleServiceError(c, err, "Station")
		return false
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return false
	}
	return true
}

// serveAudioFile sets headers and serves an audio file for download.
func serveAudioFile(c *gin.Context, filePath, filename string, bulletinID int64, cached bool) {
	if !validateAudioFile(c, filePath) {
		return
	}

	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", "audio/wav")
	c.Header("X-Bulletin-Id", strconv.FormatInt(bulletinID, 10))
	c.Header("X-Bulletin-Cached", strconv.FormatBool(cached))
	c.File(filePath)
}

// GetBulletinStories returns paginated list of stories included in a specific bulletin.
func (h *Handlers) GetBulletinStories(c *gin.Context) {
	bulletinID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	exists, err := h.bulletinSvc.Exists(c.Request.Context(), bulletinID)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Bulletin")
		return
	}

	limit, offset, ok := utils.ParsePaginationOnly(c)
	if !ok {
		return
	}

	stories, total, err := h.bulletinSvc.GetBulletinStories(c.Request.Context(), bulletinID, limit, offset)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedResponse(c, stories, total, limit, offset)
}

// GetStationBulletins returns a station's bulletins in a list envelope.
func (h *Handlers) GetStationBulletins(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if !h.requireStation(c, stationID) {
		return
	}

	if _, present := c.GetQuery("latest"); present {
		utils.ProblemValidationError(c, "Use /stations/{id}/bulletins/latest for a single bulletin", []apperrors.ValidationError{
			{Field: "latest", Message: "parameter is no longer supported on the list endpoint"},
		})
		return
	}

	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	result, err := h.bulletinSvc.GetStationBulletins(c.Request.Context(), stationID, query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetLatestStationBulletin returns the most recently generated bulletin.
func (h *Handlers) GetLatestStationBulletin(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	if !h.requireStation(c, stationID) {
		return
	}

	bulletin, err := h.bulletinSvc.GetLatest(c.Request.Context(), stationID, nil)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	c.Header("X-Cache", "HIT")
	c.Header("Age", strconv.Itoa(int(time.Since(bulletin.CreatedAt).Seconds())))
	utils.Success(c, bulletin)
}

// ListBulletins returns a paginated list of bulletins with modern query parameter support.
func (h *Handlers) ListBulletins(c *gin.Context) {
	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	result, err := h.bulletinSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetBulletin returns a single bulletin by ID.
func (h *Handlers) GetBulletin(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	bulletin, err := h.bulletinSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.Success(c, bulletin)
}

// GetStoryBulletinHistory returns bulletins that included a specific story.
// The story is checked first so an unknown story ID returns "Story" rather than
// an empty bulletin history.
func (h *Handlers) GetStoryBulletinHistory(c *gin.Context) {
	storyID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	exists, err := h.storySvc.Exists(c.Request.Context(), storyID)
	if err != nil {
		handleServiceError(c, err, "Story")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Story")
		return
	}

	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	result, err := h.bulletinSvc.GetStoryBulletinHistory(c.Request.Context(), storyID, query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetBulletinAudio serves the audio file for a specific bulletin.
func (h *Handlers) GetBulletinAudio(c *gin.Context) {
	h.ServeAudio(c, AudioConfig{
		TableName:  "bulletins",
		FilePrefix: "bulletin",
		FromOutput: true,
	})
}
