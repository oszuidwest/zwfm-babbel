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

// routeDeadlines extends only routes that perform long work or transfer audio.
func routeDeadlines(cfg *config.Config, transferMargin time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		var readTimeout, writeTimeout time.Duration
		switch c.FullPath() {
		case "/public/stations/:id/bulletin.wav":
			// Lock waiting and generation each have their own generation budget.
			writeTimeout = 2*cfg.Automation.GenerationTimeout + transferMargin
		case "/api/v1/stories/:id/tts":
			writeTimeout = cfg.TTS.RequestTimeout + transferMargin
		case "/api/v1/stories/:id/audio", "/api/v1/station-voices/:id/audio", "/api/v1/bulletins/:id/audio":
			writeTimeout = transferMargin
			if c.Request.Method == http.MethodPost {
				readTimeout = transferMargin
				writeTimeout += cfg.Automation.GenerationTimeout
			}
		}
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
