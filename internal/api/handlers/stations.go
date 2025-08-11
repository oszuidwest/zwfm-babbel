package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// ListStations returns a paginated list of all stations
func (h *Handlers) ListStations(c *gin.Context) {
	limit, offset := api.GetPagination(c)

	// Get total count
	var total int64
	if err := h.db.Get(&total, "SELECT COUNT(*) FROM stations"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count stations"})
		return
	}

	// Get paginated data
	var stations []models.Station
	if err := h.db.Select(&stations, "SELECT * FROM stations ORDER BY name ASC LIMIT ? OFFSET ?", limit, offset); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch stations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   stations,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetStation returns a single station by ID
func (h *Handlers) GetStation(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var station models.Station
	if err := h.db.Get(&station, "SELECT * FROM stations WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Station not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch station"})
		}
		return
	}

	c.JSON(http.StatusOK, station)
}

// CreateStation creates a new station
func (h *Handlers) CreateStation(c *gin.Context) {
	var req api.StationRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check name uniqueness
	if err := api.CheckUnique(h.db, "stations", "name", req.Name, nil); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Station name already exists"})
		return
	}

	// Create station
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create station"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": "Station created successfully",
	})
}

// UpdateStation updates an existing station
func (h *Handlers) UpdateStation(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var req api.StationRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check if station exists
	if !api.ValidateResourceExists(c, h.db, "stations", "Station", id) {
		return
	}

	// Check name uniqueness (excluding current record)
	if err := api.CheckUnique(h.db, "stations", "name", req.Name, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Station name already exists"})
		return
	}

	// Update station
	_, err := h.db.ExecContext(c.Request.Context(),
		"UPDATE stations SET name = ?, max_stories_per_block = ?, pause_seconds = ? WHERE id = ?",
		req.Name, req.MaxStoriesPerBlock, req.PauseSeconds, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update station"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Station updated successfully"})
}

// DeleteStation deletes a station by ID
func (h *Handlers) DeleteStation(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Check for dependencies first
	var count int
	if err := h.db.Get(&count, "SELECT COUNT(*) FROM station_voices WHERE station_id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check dependencies"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete station: it has associated voices"})
		return
	}

	// Delete station
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM stations WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete station"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Station not found"})
		return
	}

	c.Status(http.StatusNoContent)
}