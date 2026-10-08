package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

// audioTransferMargin allows slow clients to transfer audio after processing.
const audioTransferMargin = 2 * time.Minute

// routeDeadlines extends the server-wide read/write timeouts for routes that
// perform long work or transfer audio. Register them after the permission
// check so unauthenticated requests keep the short server defaults.
type routeDeadlines struct {
	automation gin.HandlerFunc
	tts        gin.HandlerFunc
	download   gin.HandlerFunc
	upload     gin.HandlerFunc
}

// newRouteDeadlines derives per-route deadlines from the configured budgets.
func newRouteDeadlines(cfg *config.Config, transferMargin time.Duration) routeDeadlines {
	return routeDeadlines{
		// Lock waiting and generation each have their own generation budget.
		automation: extendDeadlines(0, 2*cfg.Automation.GenerationTimeout+transferMargin),
		tts:        extendDeadlines(0, cfg.TTS.RequestTimeout+transferMargin),
		download:   extendDeadlines(0, transferMargin),
		upload:     extendDeadlines(transferMargin, cfg.Automation.GenerationTimeout+transferMargin),
	}
}

// extendDeadlines moves the connection deadlines before the handler starts;
// a zero duration keeps the server default.
func extendDeadlines(readTimeout, writeTimeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		controller := http.NewResponseController(c.Writer)
		if readTimeout > 0 {
			if err := controller.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
				logger.Error("Failed to extend request read deadline", "route", c.FullPath(), "error", err)
			}
		}
		if writeTimeout > 0 {
			if err := controller.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				logger.Error("Failed to extend response write deadline", "route", c.FullPath(), "error", err)
			}
		}
		c.Next()
	}
}
