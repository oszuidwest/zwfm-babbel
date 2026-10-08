package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// uploadReadTimeout replaces the server read timeout for audio upload bodies.
const uploadReadTimeout = 2 * time.Minute

// extendUploadReadDeadline gives authenticated audio uploads time to send their
// body. Register it after the permission check so anonymous requests keep the
// short server default.
func extendUploadReadDeadline(c *gin.Context) {
	if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(uploadReadTimeout)); err != nil {
		logger.Error("Failed to extend upload read deadline", "route", c.FullPath(), "error", err)
	}
	c.Next()
}
