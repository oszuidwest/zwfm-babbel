// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStations returns a paginated list of all radio stations.
func (h *Handlers) ListStations(c *gin.Context) {
	// Parse query parameters
	params := utils.ParseQueryParams(c)
	if params == nil {
		utils.ProblemInternalServer(c, "Failed to parse query parameters")
		return
	}

	// Convert utils.QueryParams to repository.ListQuery
	query := convertToListQuery(params)

	result, err := h.stationSvc.List(c.Request.Context(), query)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	// Apply field filtering if requested
	var responseData any = result.Data
	if len(params.Fields) > 0 {
		responseData = filterFields(result.Data, params.Fields)
	}

	utils.PaginatedResponse(c, responseData, result.Total, result.Limit, result.Offset)
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

	c.JSON(200, station)
}

// CreateStation creates a new radio station.
func (h *Handlers) CreateStation(c *gin.Context) {
	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	station, err := h.stationSvc.Create(c.Request.Context(), req.Name, req.MaxStoriesPerBlock, req.PauseSeconds)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.CreatedWithID(c, station.ID, "Station created successfully")
}

// UpdateStation updates an existing radio station.
func (h *Handlers) UpdateStation(c *gin.Context) {
	id, ok := utils.IDParam(c)
	if !ok {
		return
	}

	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Convert to service update request
	updateReq := &services.UpdateStationRequest{
		Name:               &req.Name,
		MaxStoriesPerBlock: &req.MaxStoriesPerBlock,
		PauseSeconds:       &req.PauseSeconds,
	}

	err := h.stationSvc.Update(c.Request.Context(), id, updateReq)
	if err != nil {
		handleServiceError(c, err, "Station")
		return
	}

	utils.SuccessWithMessage(c, "Station updated successfully")
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
