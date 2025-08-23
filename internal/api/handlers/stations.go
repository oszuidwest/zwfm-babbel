// Package handlers provides HTTP request handlers for all API endpoints.
package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
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
	utils.ModernListWithQuery(c, h.db, config, &stations)
}

// GetStation returns a single radio station by ID with all configuration details.
// Requires 'stations' read permission. Returns 404 if station doesn't exist.
func (h *Handlers) GetStation(c *gin.Context) {
	var station models.Station
	utils.GenericGetByID(c, h.db, "stations", "Station", &station)
}

// CreateStation creates a new radio station with broadcast configuration settings.
// Validates that station names are unique across the system. Requires 'stations' write permission.
// Returns 201 Created with the new station ID on success, 409 Conflict for duplicate names.
func (h *Handlers) CreateStation(c *gin.Context) {
	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Check name uniqueness
	if err := utils.CheckUnique(h.db, "stations", "name", req.Name, nil); err != nil {
		utils.ProblemDuplicate(c, "Station name")
		return
	}

	// Create station
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds,
	)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to create station due to database error")
		return
	}

	id, _ := result.LastInsertId()
	utils.CreatedWithID(c, id, "Station created successfully")
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

	// Check if station exists
	if !utils.ValidateResourceExists(c, h.db, "stations", "Station", id) {
		return
	}

	// Check name uniqueness (excluding current record)
	if err := utils.CheckUnique(h.db, "stations", "name", req.Name, &id); err != nil {
		utils.ProblemDuplicate(c, "Station name")
		return
	}

	// Update station
	_, err := h.db.ExecContext(c.Request.Context(),
		"UPDATE stations SET name = ?, max_stories_per_block = ?, pause_seconds = ? WHERE id = ?",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds, id,
	)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to update station")
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

	// Check for dependencies first
	count, err := utils.CountDependencies(h.db, "station_voices", "station_id", id)
	if err != nil {
		utils.ProblemInternalServer(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, "Cannot delete station: it has associated voices")
		return
	}

	// Delete station
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM stations WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error deleting station: %v", err)
		if strings.Contains(err.Error(), "foreign key constraint") {
			utils.ProblemCustom(c, "https://babbel.api/problems/dependency-constraint", "Dependency Constraint", 409, "Cannot delete station: it is referenced by other resources")
		} else {
			utils.ProblemInternalServer(c, "Failed to delete station due to database error")
		}
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.ProblemNotFound(c, "Station")
		return
	}

	utils.NoContent(c)
}
