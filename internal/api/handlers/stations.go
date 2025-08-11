package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// ListStations returns a paginated list of all stations
func (h *Handlers) ListStations(c *gin.Context) {
	var stations []models.Station
	utils.GenericList(c, h.db, "stations", "*", &stations)
}

// GetStation returns a single station by ID
func (h *Handlers) GetStation(c *gin.Context) {
	var station models.Station
	utils.GenericGetByID(c, h.db, "stations", "Station", &station)
}

// CreateStation creates a new station
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

// UpdateStation updates an existing station
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

// DeleteStation deletes a station by ID
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
		utils.InternalServerError(c, "Failed to delete station")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		utils.NotFound(c, "Station")
		return
	}

	utils.NoContent(c)
}
