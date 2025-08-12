package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// ListStations returns a paginated list of all radio stations with their configuration.
func (h *Handlers) ListStations(c *gin.Context) {
	var stations []models.Station
	utils.GenericList(c, h.db, "stations", "*", &stations)
}

// GetStation returns a single radio station by ID with all its configuration details.
func (h *Handlers) GetStation(c *gin.Context) {
	var station models.Station
	utils.GenericGetByID(c, h.db, "stations", "Station", &station)
}

// CreateStation creates a new radio station with the provided configuration and validates uniqueness.
func (h *Handlers) CreateStation(c *gin.Context) {
	var req utils.StationRequest
	if !utils.BindAndValidate(c, &req) {
		return
	}

	// Check name uniqueness
	if err := utils.CheckUnique(h.db, "stations", "name", req.Name, nil); err != nil {
		utils.BadRequest(c, "Station name already exists")
		return
	}

	// Create station
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds,
	)
	if err != nil {
		utils.InternalServerError(c, "Failed to create station")
		return
	}

	id, _ := result.LastInsertId()
	utils.CreatedWithID(c, id, "Station created successfully")
}

// UpdateStation updates an existing radio station with new configuration while validating uniqueness.
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
		utils.BadRequest(c, "Station name already exists")
		return
	}

	// Update station
	_, err := h.db.ExecContext(c.Request.Context(),
		"UPDATE stations SET name = ?, max_stories_per_block = ?, pause_seconds = ? WHERE id = ?",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds, id,
	)
	if err != nil {
		utils.InternalServerError(c, "Failed to update station")
		return
	}

	utils.SuccessWithMessage(c, "Station updated successfully")
}

// DeleteStation deletes a radio station by ID after checking for dependencies like station-voices.
func (h *Handlers) DeleteStation(c *gin.Context) {
	id, ok := utils.GetIDParam(c)
	if !ok {
		return
	}

	// Check for dependencies first
	count, err := utils.CountDependencies(h.db, "station_voices", "station_id", id)
	if err != nil {
		utils.InternalServerError(c, "Failed to check dependencies")
		return
	}
	if count > 0 {
		utils.BadRequest(c, "Cannot delete station: it has associated voices")
		return
	}

	// Delete station
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM stations WHERE id = ?", id)
	if err != nil {
		logger.Error("Database error deleting station: %v", err)
		if strings.Contains(err.Error(), "foreign key constraint") {
			utils.BadRequest(c, "Cannot delete station: it is referenced by other resources")
		} else {
			utils.InternalServerError(c, "Failed to delete station due to database error")
		}
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.NotFound(c, "Station")
		return
	}

	utils.NoContent(c)
}
