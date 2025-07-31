package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// StationInput represents the request parameters for creating or updating a station.
type StationInput struct {
	Name               string  `json:"name" binding:"required"`
	MaxStoriesPerBlock int     `json:"max_stories_per_block" binding:"required,min=1,max=50"`
	PauseSeconds       float64 `json:"pause_seconds" binding:"min=0,max=10"`
}

// ListStations returns a paginated list of all stations.
func (h *Handlers) ListStations(c *gin.Context) {
	crud := NewCRUDHandler(h.db, "stations", WithOrderBy("name ASC"))

	var stations []models.Station
	filters := map[string]string{}

	total, err := crud.List(c, &stations, filters)
	if err != nil {
		responses.InternalServerError(c, err.Error())
		return
	}

	limit, offset := extractPaginationParams(c)
	responses.Paginated(c, stations, total, limit, offset)
}

// GetStation returns a single station by ID.
func (h *Handlers) GetStation(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "station")
	if !ok {
		return
	}

	crud := NewCRUDHandler(h.db, "stations")
	var station models.Station
	crud.GetByID(c, id, &station)
}

// CreateStation creates a new station.
func (h *Handlers) CreateStation(c *gin.Context) {
	var input StationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Create station
	result, err := h.db.ExecContext(c.Request.Context(),
		"INSERT INTO stations (name, max_stories_per_block, pause_seconds) VALUES (?, ?, ?)",
		input.Name, input.MaxStoriesPerBlock, input.PauseSeconds,
	)
	if err != nil {
		handleDatabaseError(c, err, "create")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		responses.InternalServerError(c, "Failed to get station ID")
		return
	}

	// Fetch the created station
	var station models.Station
	h.fetchAndRespond(c, "SELECT * FROM stations WHERE id = ?", id, &station, true)
}

// UpdateStation updates an existing station.
func (h *Handlers) UpdateStation(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "station")
	if !ok {
		return
	}

	var input StationInput
	if err := c.ShouldBindJSON(&input); err != nil {
		responses.BadRequest(c, "Invalid request body")
		return
	}

	// Check if station exists
	if !h.validateRecordExists(c, "stations", "Station", id) {
		return
	}

	// Use query builder for dynamic updates
	qb := NewQueryBuilder()
	qb.AddUpdate("name", input.Name)
	qb.AddUpdateInt("max_stories_per_block", input.MaxStoriesPerBlock)
	qb.AddUpdateFloat("pause_seconds", input.PauseSeconds, true)

	if qb.HasUpdates() {
		query, args := qb.BuildUpdateQuery("stations", id)
		if _, err := h.db.ExecContext(c.Request.Context(), query, args...); err != nil {
			handleDatabaseError(c, err, "update")
			return
		}
	}

	// Fetch updated station
	var station models.Station
	h.fetchAndRespond(c, "SELECT * FROM stations WHERE id = ?", id, &station, false)
}

// DeleteStation deletes a station by ID.
func (h *Handlers) DeleteStation(c *gin.Context) {
	id, ok := validateAndGetIDParam(c, "station")
	if !ok {
		return
	}

	crud := NewCRUDHandler(h.db, "stations")
	crud.Delete(c, id)
}
