package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestExtendUploadReadDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const readTimeout = 40 * time.Millisecond
	payload := strings.Repeat("audio", 4096)
	router := gin.New()
	router.POST("/upload", extendUploadReadDeadline, func(c *gin.Context) {
		data, err := io.ReadAll(c.Request.Body)
		if err != nil || string(data) != payload {
			t.Errorf("upload = %d bytes, %v; want %d bytes", len(data), err, len(payload))
		}
		c.Status(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(router)
	server.Config.ReadTimeout = readTimeout
	server.Start()
	defer server.Close()

	// The body arrives after the server read timeout has passed.
	body, writer := io.Pipe()
	go func() {
		time.Sleep(3 * readTimeout)
		_, err := io.WriteString(writer, payload)
		writer.CloseWithError(err)
	}()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.StatusCode)
	}
}
