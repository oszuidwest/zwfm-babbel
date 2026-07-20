package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStations returns a paginated list of all radio stations.
func (h *Handlers) ListStations(c *gin.Context) {
	params, query, ok := utils.ParseListQuery(c)
	if !ok {
		return
	}

	result, err := h.stationSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.PaginatedListResponse(c, params, result)
}

// GetStation returns a single radio station by ID.
func (h *Handlers) GetStation(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	station, err := h.stationSvc.GetByID(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.Success(c, station)
}

// defaultPauseSeconds is the pause between bulletin stories when a station
// request omits pause_seconds.
const defaultPauseSeconds = 2.0

// resolvePauseSeconds applies the default pause for omitted pause_seconds
// while preserving an explicit 0.
func resolvePauseSeconds(pauseSeconds *float64) float64 {
	if pauseSeconds == nil {
		return defaultPauseSeconds
	}
	return *pauseSeconds
}

// CreateStation accepts a JSON station payload and persists a radio station.
func (h *Handlers) CreateStation(c *gin.Context) {
	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	station, err := h.stationSvc.Create(c.Request.Context(), req.Name, req.MaxStoriesPerBlock, resolvePauseSeconds(req.PauseSeconds))
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.CreatedWithLocation(c, station.ID, "/api/v1/stations", "Station created successfully")
}

// UpdateStation replaces the editable station configuration fields.
func (h *Handlers) UpdateStation(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	pauseSeconds := resolvePauseSeconds(req.PauseSeconds)
	updateReq := &services.UpdateStationRequest{
		Name:               &req.Name,
		MaxStoriesPerBlock: &req.MaxStoriesPerBlock,
		PauseSeconds:       &pauseSeconds,
	}

	updated, err := h.stationSvc.Update(c.Request.Context(), id, updateReq)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}
	utils.Success(c, updated)
}

// DeleteStation removes a radio station.
func (h *Handlers) DeleteStation(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	err := h.stationSvc.Delete(c.Request.Context(), id)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.NoContent(c)
}
