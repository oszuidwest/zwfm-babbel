package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

type failedAudioReader struct {
	io.ReadSeeker
	err error
}

type disconnectedAudioWriter struct{ *httptest.ResponseRecorder }

func (disconnectedAudioWriter) Write([]byte) (int, error) {
	return 0, errors.New("client connection closed")
}

type blockedAudioReader struct {
	io.ReadSeeker
	started, release chan struct{}
}

func (r blockedAudioReader) Read([]byte) (int, error) {
	close(r.started)
	<-r.release
	return 0, io.ErrClosedPipe
}

func TestAudioReadTrackerInspectionDoesNotWaitForInFlightIO(t *testing.T) {
	t.Parallel()
	started, release, readDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	reader := &audioReadTracker{source: blockedAudioReader{strings.NewReader(""), started, release}, size: 10}
	go func() { _, _ = reader.Read(make([]byte, 1)); close(readDone) }()
	<-started
	inspected := make(chan error, 1)
	go func() { inspected <- reader.failure() }()
	select {
	case err := <-inspected:
		if err != nil {
			t.Errorf("inspection before read completion = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("failure inspection waited for unfinished I/O")
	}
	close(release)
	<-readDone
}

func TestAudioReadTrackerDoesNotLabelWriterFailureAsStorageFailure(t *testing.T) {
	t.Parallel()
	reader := &audioReadTracker{source: strings.NewReader("0123456789"), size: 10}
	writer := disconnectedAudioWriter{httptest.NewRecorder()}
	http.ServeContent(writer, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/audio", nil), "story.wav", time.Now(), reader)
	if err := reader.failure(); err != nil {
		t.Fatalf("client write failure classified as storage failure: %v", err)
	}
}

func (r failedAudioReader) Read([]byte) (int, error) { return 0, r.err }

func TestAudioReadTrackerCapturesReadCauseAndPrematureEOF(t *testing.T) {
	t.Parallel()
	cause := errors.New("disk I/O error")
	for _, tt := range []struct {
		name   string
		source io.ReadSeeker
		size   int64
		want   error
	}{
		{"disk error", failedAudioReader{strings.NewReader("audio"), cause}, 5, cause},
		{"short file", strings.NewReader("abc"), 5, io.ErrUnexpectedEOF},
		{"complete", strings.NewReader("abcde"), 5, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := &audioReadTracker{source: tt.source, size: tt.size}
			_, _ = io.Copy(io.Discard, reader)
			if !errors.Is(reader.failure(), tt.want) {
				t.Fatalf("failure = %v, want %v", reader.failure(), tt.want)
			}
		})
	}
}

func TestServeAudioLogsTruncatedFileAfterHeaders(t *testing.T) {
	for _, byteRange := range []string{"", "bytes=1-4", "bytes=0-0,3-4"} {
		t.Run(byteRange, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "story.wav")
			if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
				t.Fatal(err)
			}
			h := &Handlers{audioRepo: audioPathRepository{path: "story.wav"}, config: &config.Config{Audio: config.AudioConfig{ProcessedPath: dir}}}
			c, rec := newProblemContext(t)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stories/7/audio", nil)
			c.Request.Header.Set("Range", byteRange)
			c.Params = gin.Params{{Key: "id", Value: "7"}}
			c.Writer = audioFileChangingWriter{c.Writer, func() {
				if err := os.Truncate(path, 0); err != nil {
					t.Error(err)
				}
			}}
			logs := testutil.CaptureLogs(t, slog.LevelDebug)
			h.ServeAudio(c, AudioConfig{TableName: "stories", FilePrefix: "story"})
			var record map[string]any
			if rec.Code >= 400 || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" || record["resource"] != "stories" || record["path"] != path || record["id"] != float64(7) ||
				!strings.Contains(record["error"].(string), io.ErrUnexpectedEOF.Error()) {
				t.Fatalf("status = %d, logs = %s; want the storage failure after successful headers", rec.Code, logs)
			}
		})
	}
}

func TestAudioReadTrackerKeepsValidConditionalAndRangeResponses(t *testing.T) {
	for _, tt := range []struct {
		method, rangeHeader, modified string
		status                        int
	}{
		{http.MethodGet, "", "", 200}, {http.MethodGet, "bytes=1-3", "", 206}, {http.MethodGet, "bytes=0-0,3-4", "", 206},
		{http.MethodHead, "", "", 200}, {http.MethodGet, "", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), 304},
	} {
		t.Run(tt.method+tt.rangeHeader+tt.modified, func(t *testing.T) {
			reader := &audioReadTracker{source: strings.NewReader("0123456789"), size: 10}
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), tt.method, "/audio", nil)
			req.Header.Set("Range", tt.rangeHeader)
			req.Header.Set("If-Modified-Since", tt.modified)
			http.ServeContent(rec, req, "story.wav", time.Now().Add(-time.Hour), reader)
			if rec.Code != tt.status || reader.failure() != nil {
				t.Fatalf("status = %d, failure = %v", rec.Code, reader.failure())
			}
		})
	}
}
