package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

// audioPathRepository returns a fixed audio lookup result.
type audioPathRepository struct {
	path string
	err  error
}

func (r audioPathRepository) GetFilePath(context.Context, string, int64) (string, error) {
	return r.path, r.err
}

// A row that names a file missing on disk returns 404 and logs one Warn
// record with the resource, id and path. It sends no alert.
func TestServeAudio_MissingFileLogsWarning(t *testing.T) {
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	dir := t.TempDir()
	h := NewHandlers(HandlersDeps{
		AudioRepo: audioPathRepository{path: "story_7.wav"},
		Config:    &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}},
	})
	c, recorder := newProblemContext(t)
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/stories/7/audio", nil)
	c.Params = gin.Params{{Key: "id", Value: "7"}}
	alerts := &automationAlertRecorder{}
	c.Set(alertContextKey, alerts)

	h.ServeAudio(c, AudioConfig{TableName: "stories", FilePrefix: "story"})

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	// Unmarshal rejects an empty buffer and a second record.
	var record map[string]any
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil || record["level"] != "WARN" {
		t.Fatalf("logs = %s, want one WARN record", logs)
	}
	wantPath := filepath.Join(dir, "story_7.wav")
	if record["resource"] != "stories" || record["id"] != float64(7) || record["path"] != wantPath {
		t.Fatalf("record = %v, want resource stories, id 7 and path %s", record, wantPath)
	}
	if len(alerts.events) != 0 {
		t.Fatalf("alerts = %d, want 0", len(alerts.events))
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
