// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStations returns a paginated list of all radio stations with their configuration.
// Supports modern query parameters: search, filtering, sorting, field selection, and pagination.
// Requires 'stations' read permission. Returns station data with metadata including total count and pagination info.
func (h *Handlers) ListStations(c *gin.Context) {
	h.stationSvc.ListWithContext(c)
}

// GetStation returns a single radio station by ID with all configuration details.
// Requires 'stations' read permission. Returns 404 if station doesn't exist.
func (h *Handlers) GetStation(c *gin.Context) {
	h.stationSvc.GetByIDWithContext(c)
}

// CreateStation creates a new radio station with broadcast configuration settings.
// Validates that station names are unique across the system. Requires 'stations' write permission.
// Returns 201 Created with the new station ID on success, 409 Conflict for duplicate names.
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

// UpdateStation updates an existing radio station's configuration settings.
// Validates station existence and name uniqueness (excluding current station).
// Requires 'stations' write permission. Returns 404 if station doesn't exist, 409 for name conflicts.
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

// DeleteStation removes a radio station after validating no dependencies exist.
// Checks for associated station-voices and other references before deletion.
// Requires 'stations' write permission. Returns 409 Conflict if dependencies exist, 404 if not found.
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
