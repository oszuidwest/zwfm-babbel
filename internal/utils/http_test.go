package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	InitializeValidators()
	os.Exit(m.Run())
}

// NormalizeText tests for StoryCreateRequest.

func TestStoryCreateRequest_NormalizeText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		title     string
		text      string
		wantTitle string
		wantText  string
	}{
		{
			name:      "decodes common HTML entities",
			title:     "Tom &amp; Jerry",
			text:      "Use &lt;strong&gt; tags",
			wantTitle: "Tom & Jerry",
			wantText:  "Use <strong> tags",
		},
		{
			name:      "decodes numeric entities",
			title:     "caf&#233;",
			text:      "&#169; 2024",
			wantTitle: "café",
			wantText:  "© 2024",
		},
		{
			name:      "passes through plain text unchanged",
			title:     "Plain title",
			text:      "Plain text",
			wantTitle: "Plain title",
			wantText:  "Plain text",
		},
		{
			name:      "handles empty strings",
			title:     "",
			text:      "",
			wantTitle: "",
			wantText:  "",
		},
		{
			name:      "single decode of double-encoded entities",
			title:     "&amp;amp;",
			text:      "&amp;lt;",
			wantTitle: "&amp;",
			wantText:  "&lt;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := &StoryCreateRequest{Title: tt.title, Text: tt.text}
			req.NormalizeText()
			if req.Title != tt.wantTitle {
				t.Errorf("Title = %q, want %q", req.Title, tt.wantTitle)
			}
			if req.Text != tt.wantText {
				t.Errorf("Text = %q, want %q", req.Text, tt.wantText)
			}
		})
	}
}

// NormalizeText tests for StoryUpdateRequest.

func TestStoryUpdateRequest_NormalizeText(t *testing.T) {
	t.Parallel()

	t.Run("decodes non-nil fields", func(t *testing.T) {
		t.Parallel()
		title := "Tom &amp; Jerry"
		text := "Use &lt;b&gt; tags"
		req := &StoryUpdateRequest{Title: &title, Text: &text}
		req.NormalizeText()

		if *req.Title != "Tom & Jerry" {
			t.Errorf("Title = %q, want %q", *req.Title, "Tom & Jerry")
		}
		if *req.Text != "Use <b> tags" {
			t.Errorf("Text = %q, want %q", *req.Text, "Use <b> tags")
		}
	})

	t.Run("handles nil fields without panic", func(t *testing.T) {
		t.Parallel()
		req := &StoryUpdateRequest{Title: nil, Text: nil}
		req.NormalizeText()

		if req.Title != nil {
			t.Error("Title should remain nil")
		}
		if req.Text != nil {
			t.Error("Text should remain nil")
		}
	})

	t.Run("handles mixed nil and non-nil", func(t *testing.T) {
		t.Parallel()
		text := "&amp; more"
		req := &StoryUpdateRequest{Title: nil, Text: &text}
		req.NormalizeText()

		if req.Title != nil {
			t.Error("Title should remain nil")
		}
		if *req.Text != "& more" {
			t.Errorf("Text = %q, want %q", *req.Text, "& more")
		}
	})
}

// BindAndValidate tests.

// problemResponse is the subset of the RFC 9457 response we assert on.
type problemResponse struct {
	Errors []apperrors.ValidationError `json:"errors"`
}

// assertValidationError checks that the response contains a validation error for the given field
// with a message that contains the given substring.
func assertValidationError(t *testing.T, w *httptest.ResponseRecorder, field, msgSubstring string) {
	t.Helper()
	var resp problemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	for _, e := range resp.Errors {
		if e.Field == field && strings.Contains(e.Message, msgSubstring) {
			return
		}
	}
	t.Errorf("expected validation error on field %q containing %q, got errors: %+v", field, msgSubstring, resp.Errors)
}

func newTestContext(t *testing.T, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), "POST", "/test", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

// bindExpect is a named type (not a struct alias) so checkBindResult callers
// share one concrete type definition.
type bindExpect struct {
	ok         bool
	status     int
	errField   string
	errMessage string
}

func TestBindAndValidate(t *testing.T) {
	t.Parallel()

	// Boundary inputs: max=500 applies to the *decoded* value.
	// "A"*496 + "&amp;" = 501 encoded -> 497 decoded (allowed).
	// "A"*500 + "&amp;" = 505 encoded -> 501 decoded (rejected).
	titleAt497 := strings.Repeat("A", 496) + "&amp;"
	titleAt501 := strings.Repeat("A", 500) + "&amp;"

	storyCases := []struct {
		name   string
		body   string
		want   bindExpect
		verify func(t *testing.T, req *StoryCreateRequest)
	}{
		{
			name: "valid request decodes nothing",
			body: `{"title":"Test Story","text":"Some content","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if req.Title != "Test Story" || req.Text != "Some content" {
					t.Errorf("got Title=%q Text=%q", req.Title, req.Text)
				}
			},
		},
		{
			name: "malformed JSON",
			body: `{invalid json}`,
			want: bindExpect{status: 422},
		},
		{
			name: "empty body",
			body: "",
			want: bindExpect{status: 422},
		},
		{
			name: "missing required title",
			body: `{"text":"Some content","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{status: 422, errField: "Title", errMessage: "required"},
		},
		{
			name: "whitespace-only title rejected by notblank",
			body: `{"title":"   ","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{status: 422, errField: "Title", errMessage: "empty or whitespace"},
		},
		{
			name: "entities decoded before validation",
			body: `{"title":"Tom &amp; Jerry","text":"Content &lt;here&gt;","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if req.Title != "Tom & Jerry" || req.Text != "Content <here>" {
					t.Errorf("entities not decoded: Title=%q Text=%q", req.Title, req.Text)
				}
			},
		},
		{
			name: "invalid story status",
			body: `{"title":"Test","text":"content","status":"invalid_status","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{status: 422, errField: "Status", errMessage: "must be one of"},
		},
		{
			name: "invalid date format",
			body: `{"title":"Test","text":"content","start_date":"not-a-date","end_date":"2024-12-31"}`,
			want: bindExpect{status: 422, errField: "StartDate", errMessage: "YYYY-MM-DD"},
		},
		{
			name: "max length applies to decoded value (passes)",
			body: `{"title":"` + titleAt497 + `","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if len(req.Title) != 497 {
					t.Errorf("decoded Title length = %d, want 497", len(req.Title))
				}
			},
		},
		{
			name: "max length applies to decoded value (rejects)",
			body: `{"title":"` + titleAt501 + `","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`,
			want: bindExpect{status: 422, errField: "Title", errMessage: "cannot exceed 500"},
		},
	}

	for _, tt := range storyCases {
		t.Run("StoryCreateRequest/"+tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, tt.body)
			var req StoryCreateRequest
			ok := BindAndValidate(c, &req)

			checkBindResult(t, w, ok, tt.want)
			if ok && tt.verify != nil {
				tt.verify(t, &req)
			}
		})
	}

	// StoryUpdateRequest uses pointer fields - verify the boundary on the update path.
	updateCases := []struct {
		name string
		body string
		want bindExpect
	}{
		{name: "max length passes on update", body: `{"title":"` + titleAt497 + `"}`, want: bindExpect{ok: true}},
		{name: "max length rejects on update", body: `{"title":"` + titleAt501 + `"}`, want: bindExpect{status: 422, errField: "Title", errMessage: "cannot exceed 500"}},
	}
	for _, tt := range updateCases {
		t.Run("StoryUpdateRequest/"+tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, tt.body)
			var req StoryUpdateRequest
			ok := BindAndValidate(c, &req)
			checkBindResult(t, w, ok, tt.want)
			if tt.want.ok && (req.Title == nil || len(*req.Title) != 497) {
				t.Errorf("decoded Title length = %v, want 497", req.Title)
			}
		})
	}
}

// TestBindAndValidate_StationRequest covers the non-normalizer branch:
// StationRequest has no NormalizeText hook, so binding skips entity decoding.
func TestBindAndValidate_StationRequest(t *testing.T) {
	t.Parallel()

	t.Run("valid non-normalizer type", func(t *testing.T) {
		t.Parallel()
		c, w := newTestContext(t, `{"name":"Test Station","max_stories_per_block":5,"pause_seconds":1.5}`)
		var req StationRequest
		ok := BindAndValidate(c, &req)
		checkBindResult(t, w, ok, bindExpect{ok: true})
		if req.Name != "Test Station" || req.MaxStoriesPerBlock != 5 {
			t.Errorf("got Name=%q MaxStoriesPerBlock=%d", req.Name, req.MaxStoriesPerBlock)
		}
	})
	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		c, w := newTestContext(t, `{"name":"Test","max_stories_per_block":"five","pause_seconds":1.5}`)
		var req StationRequest
		ok := BindAndValidate(c, &req)
		checkBindResult(t, w, ok, bindExpect{status: 422})
	})
}

func checkBindResult(t *testing.T, w *httptest.ResponseRecorder, ok bool, want bindExpect) {
	t.Helper()
	if want.ok {
		if !ok {
			t.Fatalf("expected ok=true, got false; response: %s", w.Body.String())
		}
		return
	}
	if ok {
		t.Fatalf("expected ok=false, got true")
	}
	if want.status != 0 && w.Code != want.status {
		t.Errorf("status = %d, want %d", w.Code, want.status)
	}
	if want.errField != "" {
		assertValidationError(t, w, want.errField, want.errMessage)
	}
}

func TestBindOptionalJSON(t *testing.T) {
	t.Parallel()
	type optionalRequest struct {
		Date string `json:"date"`
	}

	tests := []struct {
		name       string
		body       string
		wantOK     bool
		wantStatus int
		wantDate   string
	}{
		{
			name:   "empty body is accepted",
			body:   "",
			wantOK: true,
		},
		{
			name:   "whitespace body is accepted",
			body:   " \n\t ",
			wantOK: true,
		},
		{
			name:     "valid json is decoded",
			body:     `{"date":"2026-05-23"}`,
			wantOK:   true,
			wantDate: "2026-05-23",
		},
		{
			name:       "malformed json is rejected",
			body:       `{invalid json}`,
			wantOK:     false,
			wantStatus: 422,
		},
		{
			name:       "oversized body is rejected",
			body:       strings.Repeat("a", int(maxJSONRequestBodyBytes)+1),
			wantOK:     false,
			wantStatus: 413,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, tt.body)

			var req optionalRequest
			ok := BindOptionalJSON(c, &req)

			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v; response: %s", ok, tt.wantOK, w.Body.String())
			}
			if tt.wantStatus != 0 && w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if req.Date != tt.wantDate {
				t.Fatalf("Date = %q, want %q", req.Date, tt.wantDate)
			}
		})
	}
}

func TestBindOptionalJSON_NilBodyGuard(t *testing.T) {
	t.Parallel()
	c, w := newTestContext(t, "")
	c.Request.Body = nil

	var req struct {
		Date string `json:"date"`
	}
	ok := BindOptionalJSON(c, &req)

	if !ok {
		t.Fatalf("expected true for nil request body; response: %s", w.Body.String())
	}
	if w.Code != 200 {
		t.Fatalf("status = %d, want default 200 (no response written)", w.Code)
	}
}

func TestBindOptionalJSON_ReadFailure(t *testing.T) {
	t.Parallel()
	c, w := newTestContext(t, "")
	c.Request.Body = failingReadCloser{}

	var req struct {
		Date string `json:"date"`
	}
	ok := BindOptionalJSON(c, &req)

	if ok {
		t.Fatal("expected false for read failure")
	}
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("read failed")
}

func (failingReadCloser) Close() error {
	return nil
}

// Double-encoded entity pipeline documenting the full write-read decode behavior.

func TestDoubleEncodedEntities_FullPipeline(t *testing.T) {
	t.Parallel()
	// Documents the edge case where double-encoded entities are decoded twice
	// across the write and read paths:
	//   Input → NormalizeText (decode #1) → stored in DB → AfterFind (decode #2) → output

	// Step 1: NormalizeText decodes once on input
	req := &StoryCreateRequest{
		Title: "&amp;amp;",
		Text:  "&amp;lt;script&amp;gt;",
	}
	req.NormalizeText()

	if req.Title != "&amp;" {
		t.Errorf("after NormalizeText: Title = %q, want %q", req.Title, "&amp;")
	}
	if req.Text != "&lt;script&gt;" {
		t.Errorf("after NormalizeText: Text = %q, want %q", req.Text, "&lt;script&gt;")
	}

	// Step 2: Simulate DB round-trip - AfterFind decodes again on read
	story := &models.Story{
		Title: req.Title,
		Text:  req.Text,
	}
	if err := story.AfterFind(nil); err != nil {
		t.Fatalf("AfterFind error: %v", err)
	}

	if story.Title != "&" {
		t.Errorf("after AfterFind: Title = %q, want %q", story.Title, "&")
	}
	if story.Text != "<script>" {
		t.Errorf("after AfterFind: Text = %q, want %q", story.Text, "<script>")
	}
}
