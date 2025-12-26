// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStations returns a paginated list of all radio stations with their configuration.
// Supports modern query parameters: search, filtering, sorting, field selection, and pagination.
// Requires 'stations' read permission. Returns station data with metadata including total count and pagination info.
func (h *Handlers) ListStations(c *gin.Context) {
	// Configure modern query with field mappings and search fields
	config := utils.EnhancedQueryConfig{
		QueryConfig: utils.QueryConfig{
			BaseQuery:    "SELECT s.* FROM stations s",
			CountQuery:   "SELECT COUNT(*) FROM stations s",
			DefaultOrder: "s.name ASC",
		},
		SearchFields:      []string{"s.name"},
		TableAlias:        "s",
		DefaultFields:     "s.*",
		DisableSoftDelete: true, // Stations table doesn't have deleted_at column
		FieldMapping: map[string]string{
			"id":                    "s.id",
			"name":                  "s.name",
			"max_stories_per_block": "s.max_stories_per_block",
			"pause_seconds":         "s.pause_seconds",
			"created_at":            "s.created_at",
			"updated_at":            "s.updated_at",
		},
	}

	var stations []models.Station
	utils.ModernListWithQuery(c, h.stationSvc.DB(), config, &stations)
}

// GetStation returns a single radio station by ID with all configuration details.
// Requires 'stations' read permission. Returns 404 if station doesn't exist.
func (h *Handlers) GetStation(c *gin.Context) {
	var station models.Station
	utils.GenericGetByID(c, h.stationSvc.DB(), "stations", "Station", &station)
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

	utils.CreatedWithID(c, int64(station.ID), "Station created successfully")
}

// UpdateStation updates an existing radio station's configuration settings.
// Validates station existence and name uniqueness (excluding current station).
// Requires 'stations' write permission. Returns 404 if station doesn't exist, 409 for name conflicts.
func (h *Handlers) UpdateStation(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	err := h.stationSvc.Update(c.Request.Context(), id, req.Name, req.MaxStoriesPerBlock, req.PauseSeconds)
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
	id, ok := utils.GetIDParam(c)
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
