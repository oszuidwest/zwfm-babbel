package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

func TestRouteDeadlines(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name, method, route string
		upload              bool
	}{
		{name: "automation", method: http.MethodGet, route: "/public/stations/:id/bulletin.wav"},
		{name: "tts", method: http.MethodPost, route: "/api/v1/stories/:id/tts"},
		{name: "story download", method: http.MethodGet, route: "/api/v1/stories/:id/audio"},
		{name: "jingle download", method: http.MethodGet, route: "/api/v1/station-voices/:id/audio"},
		{name: "bulletin download", method: http.MethodGet, route: "/api/v1/bulletins/:id/audio"},
		{name: "story upload", method: http.MethodPost, route: "/api/v1/stories/:id/audio", upload: true},
		{name: "jingle upload", method: http.MethodPost, route: "/api/v1/station-voices/:id/audio", upload: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const baseTimeout = 40 * time.Millisecond
			cfg := &config.Config{
				Automation: config.AutomationConfig{GenerationTimeout: time.Second},
				TTS:        config.TTSConfig{RequestTimeout: time.Second},
			}
			router := gin.New()
			router.Use(routeDeadlines(cfg, time.Second))
			started := make(chan struct{})
			payload := strings.Repeat("audio", 4096)
			router.Handle(tt.method, tt.route, func(c *gin.Context) {
				close(started)
				if tt.upload {
					data, err := io.ReadAll(c.Request.Body)
					if err != nil || string(data) != payload {
						t.Errorf("upload = %d bytes, %v; want %d bytes", len(data), err, len(payload))
					}
				} else {
					time.Sleep(3 * baseTimeout)
				}
				c.Data(http.StatusOK, "audio/wav", []byte(payload))
			})
			server := httptest.NewUnstartedServer(router)
			server.Config.ReadTimeout = baseTimeout
			server.Config.WriteTimeout = baseTimeout
			server.Start()
			defer server.Close()
			var body io.Reader
			if tt.upload {
				reader, writer := io.Pipe()
				defer func() {
					if err := reader.Close(); err != nil {
						t.Errorf("close: %v", err)
					}
				}()
				body = reader
				go func() {
					defer func() {
						if err := writer.Close(); err != nil {
							t.Errorf("close: %v", err)
						}
					}()
					<-started
					time.Sleep(3 * baseTimeout)
					if _, err := io.WriteString(writer, payload); err != nil {
						t.Errorf("write upload: %v", err)
					}
				}()
			}
			request, err := http.NewRequestWithContext(t.Context(), tt.method, server.URL+strings.ReplaceAll(tt.route, ":id", "1"), body)
			if err != nil {
				t.Fatal(err)
			}
			client := server.Client()
			client.Timeout = 3 * time.Second
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()
			data, err := io.ReadAll(response.Body)
			if err != nil || string(data) != payload || response.StatusCode != http.StatusOK {
				t.Fatalf("response = %d bytes, status %d, %v; want full %d-byte body", len(data), response.StatusCode, err, len(payload))
			}
		})
	}
}
