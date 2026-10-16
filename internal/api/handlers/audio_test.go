package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

// audioPathRepository returns a fixed audio lookup result.
type audioPathRepository struct {
	path string
	err  error
}

func (r audioPathRepository) GetFilePath(context.Context, string, int64) (string, error) {
	return r.path, r.err
}

// Both 500 responses of an audio download log one Error record with the
// cause. Only the failed record lookup counts toward the database alert.
func TestServeAudioLogsServerFailures(t *testing.T) {
	processed := t.TempDir()
	// A path below a regular file makes stat fail with ENOTDIR, which is not
	// a missing file and also fails when the tests run as root.
	if err := os.WriteFile(filepath.Join(processed, "story.wav"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		repo       audioPathRepository
		wantField  string
		wantCause  string
		wantAlerts int
	}{
		{
			name:       "record lookup fails",
			repo:       audioPathRepository{err: errors.New("connection lost")},
			wantField:  "cause",
			wantCause:  "connection lost",
			wantAlerts: 1,
		},
		{
			name:      "file cannot be accessed",
			repo:      audioPathRepository{path: "story.wav/1.wav"},
			wantField: "error",
			wantCause: syscall.ENOTDIR.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs := captureLogs(t)
			alerts := &automationAlertRecorder{}
			h := &Handlers{audioRepo: tt.repo, config: &config.Config{Audio: config.AudioConfig{ProcessedPath: processed}}}
			router := gin.New()
			router.GET("/stories/:id/audio", func(c *gin.Context) {
				c.Set(alertContextKey, alerts)
				h.ServeAudio(c, AudioConfig{TableName: "stories", FilePrefix: "story"})
			})
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stories/1/audio", nil))

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
			}
			// Unmarshal rejects an empty buffer and a second record.
			var record map[string]any
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil || record["level"] != "ERROR" {
				t.Fatalf("logs = %s, want one ERROR record", logs)
			}
			if cause, _ := record[tt.wantField].(string); !strings.Contains(cause, tt.wantCause) {
				t.Fatalf("record = %v, want %s containing %q", record, tt.wantField, tt.wantCause)
			}
			if len(alerts.events) != tt.wantAlerts {
				t.Fatalf("alerts = %d, want %d", len(alerts.events), tt.wantAlerts)
			}
			if tt.wantAlerts > 0 && alerts.events[0].Key != "database:request:GET /stories/:id/audio" {
				t.Fatalf("alert key = %q, want the route's database alert", alerts.events[0].Key)
			}
		})
	}
}

func TestValidByteRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		size   int64
		want   bool
	}{
		{name: "omitted", size: 100, want: true},
		{name: "bounded", header: "bytes=0-9", size: 100, want: true},
		{name: "open ended", header: "bytes=10-", size: 100, want: true},
		{name: "suffix", header: "bytes=-10", size: 100, want: true},
		{name: "multiple", header: "bytes=0-9, 90-99", size: 100, want: true},
		{name: "one overlapping range", header: "bytes=0-9, 200-300", size: 100, want: true},
		{name: "empty range set", header: "bytes=", size: 100, want: true},
		{name: "zero length suffix", header: "bytes=-0", size: 100, want: false},
		{name: "wrong unit", header: "items=0-9", size: 100, want: false},
		{name: "malformed", header: "bytes=abc", size: 100, want: false},
		{name: "reversed", header: "bytes=10-5", size: 100, want: false},
		{name: "no overlap", header: "bytes=100-200", size: 100, want: false},
		{name: "empty file ignores no overlap", header: "bytes=1-2", size: 0, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validByteRange(tt.header, tt.size); got != tt.want {
				t.Fatalf("validByteRange(%q, %d) = %v, want %v", tt.header, tt.size, got, tt.want)
			}
		})
	}
}

func TestValidateAudioRange_InvalidRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		header           string
		size             int64
		wantContentRange string
	}{
		{name: "zero length file", header: "bytes=invalid", wantContentRange: "bytes */0"},
		{name: "zero length suffix", header: "bytes=-0", size: 100, wantContentRange: "bytes */100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/audio", nil)
			c.Request.Header.Set("Range", tt.header)

			if validateAudioRange(c, tt.size) {
				t.Fatal("validateAudioRange() = true, want false")
			}
			if recorder.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestedRangeNotSatisfiable)
			}
			decodeProblem(t, recorder)
			if got := recorder.Header().Get("Content-Range"); got != tt.wantContentRange {
				t.Fatalf("Content-Range = %q, want %q", got, tt.wantContentRange)
			}
		})
	}
}
