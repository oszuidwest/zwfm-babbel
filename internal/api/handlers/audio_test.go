package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

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
			if got := recorder.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type = %q, want %q", got, "application/problem+json")
			}
			if got := recorder.Header().Get("Content-Range"); got != tt.wantContentRange {
				t.Fatalf("Content-Range = %q, want %q", got, tt.wantContentRange)
			}
		})
	}
}
