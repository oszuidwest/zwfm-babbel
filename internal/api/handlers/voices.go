package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

// ListVoices returns a paginated list of all voices
func (h *Handlers) ListVoices(c *gin.Context) {
	limit, offset := api.GetPagination(c)

	// Get total count
	var total int64
	if err := h.db.Get(&total, "SELECT COUNT(*) FROM voices"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count voices"})
		return
	}

	// Get paginated data
	var voices []models.Voice
	if err := h.db.Select(&voices, "SELECT * FROM voices ORDER BY name ASC LIMIT ? OFFSET ?", limit, offset); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch voices"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   voices,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetVoice returns a single voice by ID
func (h *Handlers) GetVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var voice models.Voice
	if err := h.db.Get(&voice, "SELECT * FROM voices WHERE id = ?", id); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Voice not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch voice"})
		}
		return
	}

	c.JSON(http.StatusOK, voice)
}

// CreateVoice creates a new voice
func (h *Handlers) CreateVoice(c *gin.Context) {
	var req api.VoiceRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check name uniqueness
	if err := api.CheckUnique(h.db, "voices", "name", req.Name, nil); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Voice name already exists"})
		return
	}

	// Create voice
	result, err := h.db.ExecContext(c.Request.Context(), "INSERT INTO voices (name) VALUES (?)", req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create voice"})
		return
	}

	id, _ := result.LastInsertId()
	c.JSON(http.StatusCreated, gin.H{
		"id":      id,
		"message": "Voice created successfully",
	})
}

// UpdateVoice updates an existing voice
func (h *Handlers) UpdateVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	var req api.VoiceRequest
	if !api.BindAndValidate(c, &req) {
		return
	}

	// Check if voice exists
	if !api.ValidateResourceExists(c, h.db, "voices", "Voice", id) {
		return
	}

	// Check name uniqueness (excluding current record)
	if err := api.CheckUnique(h.db, "voices", "name", req.Name, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Voice name already exists"})
		return
	}

	// Update voice
	_, err := h.db.ExecContext(c.Request.Context(), "UPDATE voices SET name = ? WHERE id = ?", req.Name, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update voice"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Voice updated successfully"})
}

// DeleteVoice deletes a voice if it has no dependencies
func (h *Handlers) DeleteVoice(c *gin.Context) {
	id, ok := api.GetIDParam(c)
	if !ok {
		return
	}

	// Check for dependencies
	var count int
	if err := h.db.Get(&count, "SELECT COUNT(*) FROM stories WHERE voice_id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check dependencies"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete voice: it is used by stories"})
		return
	}

	// Check station_voices dependencies
	if err := h.db.Get(&count, "SELECT COUNT(*) FROM station_voices WHERE voice_id = ?", id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check dependencies"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete voice: it is used by stations"})
		return
	}

	// Delete voice
	result, err := h.db.ExecContext(c.Request.Context(), "DELETE FROM voices WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete voice"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Voice not found"})
		return
	}

	c.Status(http.StatusNoContent)
}