package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const uploadReadTimeout = 2 * time.Minute

// extendUploadReadDeadline extends the deadline for audio upload bodies.
// Register it after permission checks to retain the default for unauthorized requests.
func extendUploadReadDeadline(c *gin.Context) {
	if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(uploadReadTimeout)); err != nil {
		logger.Error("Failed to extend upload read deadline", "route", c.FullPath(), "error", err)
	}
	c.Next()
}
