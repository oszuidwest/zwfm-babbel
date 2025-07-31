package handlers

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/api/responses"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// Handlers contains all the dependencies needed by the API handlers.
type Handlers struct {
	db       *sqlx.DB
	audioSvc *audio.Service
	config   *config.Config
}

// NewHandlers creates a new Handlers instance with the given dependencies.
func NewHandlers(db *sqlx.DB, audioSvc *audio.Service, cfg *config.Config) *Handlers {
	return &Handlers{
		db:       db,
		audioSvc: audioSvc,
		config:   cfg,
	}
}

func extractPaginationParams(c *gin.Context) (limit, offset int) {
	limit = 20
	offset = 0

	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}

	return
}

func getBoolQuery(c *gin.Context, name string) bool {
	value := c.Query(name)
	return value == "true" || value == "1"
}

func getIntForm(c *gin.Context, name string, defaultValue int) int {
	value := c.PostForm(name)
	if value == "" {
		return defaultValue
	}
	if i, err := strconv.Atoi(value); err == nil {
		return i
	}
	return defaultValue
}

func getFloatForm(c *gin.Context, name string, defaultValue float64) float64 {
	value := c.PostForm(name)
	if value == "" {
		return defaultValue
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f
	}
	return defaultValue
}

func getIDParam(c *gin.Context) (int, error) {
	return strconv.Atoi(c.Param("id"))
}

// validateAndGetIDParam is a DRY helper that combines ID parameter extraction and validation
func validateAndGetIDParam(c *gin.Context, resourceName string) (int, bool) {
	id, err := getIDParam(c)
	if err != nil {
		responses.BadRequest(c, fmt.Sprintf("Invalid %s ID", resourceName))
		return 0, false
	}
	return id, true
}

// recordExists is a DRY helper for checking if a record exists in any table
func (h *Handlers) recordExists(tableName string, id int) (bool, error) {
	var exists bool
	query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE id = ?)", tableName)
	err := h.db.Get(&exists, query, id)
	return exists, err
}

// validateRecordExists checks if a record exists and responds with error if not
func (h *Handlers) validateRecordExists(c *gin.Context, tableName, resourceName string, id int) bool {
	exists, err := h.recordExists(tableName, id)
	if err != nil {
		responses.InternalServerError(c, fmt.Sprintf("Failed to check %s existence", resourceName))
		return false
	}
	if !exists {
		responses.NotFound(c, fmt.Sprintf("%s not found", resourceName))
		return false
	}
	return true
}

// fetchAndRespond is a DRY helper for fetching a record after create/update and responding
func (h *Handlers) fetchAndRespond(c *gin.Context, query string, id interface{}, dest interface{}, isCreate bool) {
	if err := h.db.Get(dest, query, id); err != nil {
		action := "updated"
		if isCreate {
			action = "created"
		}
		responses.InternalServerError(c, fmt.Sprintf("Failed to fetch %s record", action))
		return
	}

	if isCreate {
		responses.Created(c, dest)
	} else {
		responses.Success(c, dest)
	}
}

// isLastAdmin checks if the given user is the last admin and handles the appropriate response
func (h *Handlers) isLastAdmin(c *gin.Context, userID int) (bool, bool) {
	// Get count of other active admin users
	var adminCount int
	if err := h.db.Get(&adminCount, "SELECT COUNT(*) FROM users WHERE role = 'admin' AND suspended_at IS NULL AND id != ?", userID); err != nil {
		responses.InternalServerError(c, "Failed to check admin count")
		return false, true // shouldReturn = true
	}

	// Get user's role
	var userRole string
	if err := h.db.Get(&userRole, "SELECT role FROM users WHERE id = ?", userID); err != nil {
		if err.Error() == "sql: no rows in result set" {
			responses.NotFound(c, "User not found")
		} else {
			responses.InternalServerError(c, "Failed to fetch user")
		}
		return false, true // shouldReturn = true
	}

	// Check if this would affect the last admin
	isLastAdmin := userRole == "admin" && adminCount == 0
	return isLastAdmin, false // shouldReturn = false
}

// stationExists checks if a station exists in the database
func (h *Handlers) stationExists(stationID int) bool {
	var exists bool
	if err := h.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM stations WHERE id = ?)", stationID); err != nil {
		// If there's an error, we assume the station doesn't exist
		return false
	}
	return exists
}

// dateToWeekdayBitmask converts a date to weekday bitmask for database queries
func dateToWeekdayBitmask(date time.Time) uint8 {
	// Convert Go's weekday (Sunday=0) to our weekday bitmask (Monday=1)
	// #nosec G115 - weekday calculation always results in 0-6, safe for uint8
	return uint8(1 << uint((int(date.Weekday())+6)%7))
}
