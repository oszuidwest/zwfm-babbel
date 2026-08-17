package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// GenerateBulletin queues durable asynchronous bulletin generation.
func (h *Handlers) GenerateBulletin(c *gin.Context) {
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

	exists, err := h.stationSvc.Exists(c.Request.Context(), stationID)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return
	}

	job, err := h.bulletinJobSvc.Enqueue(c.Request.Context(), stationID, targetDate)
	if err != nil {
		handleServiceError(c, err, "Bulletin job")
		return
	}

	c.Header("Location", fmt.Sprintf("/api/v1/bulletin-jobs/%d", job.ID))
	c.JSON(http.StatusAccepted, job)
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

// setCacheHeaders sets standardized cache response headers.
func setCacheHeaders(c *gin.Context, createdAt time.Time, hit bool) {
	if hit {
		c.Header("X-Cache", "HIT")
		c.Header("Age", strconv.Itoa(int(time.Since(createdAt).Seconds())))
	} else {
		c.Header("X-Cache", "MISS")
		c.Header("Age", "0")
	}
}

// serveAudioFile sets headers and serves an audio file for download.
func serveAudioFile(c *gin.Context, filePath, filename string, bulletinID int64, cached bool) {
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

// GetStationBulletins returns a station's bulletins.
// The latest=true shortcut is intentionally stricter than normal listing:
// filter, sort, search, fields, trashed, offset, and limit values other than 1
// are rejected because the shortcut returns at most one bulletin.
func (h *Handlers) GetStationBulletins(c *gin.Context) {
	stationID, ok := utils.IDParam(c)
	if !ok {
		return
	}

	exists, err := h.stationSvc.Exists(c.Request.Context(), stationID)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}
	if !exists {
		utils.ProblemNotFound(c, "Station")
		return
	}

	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	// The latest-bulletin shortcut returns before repository-side whitelist
	// enforcement runs, so ParseListQuery alone cannot catch unknown
	// filter/sort/fields. Reject those here so latest=true&filter[bogus]=1 does
	// not silently succeed. `limit=1` is the trigger so it remains allowed;
	// everything else must be absent.
	if c.Query("latest") == "true" || c.Query("limit") == "1" {
		if !rejectIfNotPureLatest(c, params) {
			return
		}
		bulletin, err := h.bulletinSvc.GetLatest(c.Request.Context(), stationID, nil)
		if err != nil {
			utils.ProblemNotFound(c, "No bulletin found for this station")
			return
		}

		setCacheHeaders(c, bulletin.CreatedAt, true)

		utils.Success(c, bulletin)
		return
	}

	result, err := h.bulletinSvc.GetStationBulletins(c.Request.Context(), stationID, query)
	if err != nil {
		handleServiceError(c, err, "Bulletin")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// rejectIfNotPureLatest enforces that the latest-bulletin shortcut sees no
// list-query parameters beyond the trigger itself (?latest=true and/or
// limit=1). Returns false after writing a 422 response on violation.
func rejectIfNotPureLatest(c *gin.Context, params *utils.QueryParams) bool {
	var unsupported []apperrors.ValidationError
	if len(params.Filters) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "filter", Message: "not supported with latest=true"})
	}
	if len(params.Sort) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "sort", Message: "not supported with latest=true"})
	}
	if len(params.Fields) > 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "fields", Message: "not supported with latest=true"})
	}
	if params.Search != "" {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "search", Message: "not supported with latest=true"})
	}
	if params.Trashed != "" {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "trashed", Message: "not supported with latest=true"})
	}
	if params.Offset != 0 {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "offset", Message: "not supported with latest=true"})
	}
	// Explicit limit must be exactly "1" or absent. limit=2 with latest=true
	// is contradictory because the shortcut only returns one bulletin.
	if raw := c.Query("limit"); raw != "" && raw != "1" {
		unsupported = append(unsupported, apperrors.ValidationError{Field: "limit", Message: "must be 1 (or omitted) when latest=true"})
	}
	if len(unsupported) > 0 {
		utils.ProblemValidationError(c, "latest=true returns a single bulletin; remove other query parameters", unsupported)
		return false
	}
	return true
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
