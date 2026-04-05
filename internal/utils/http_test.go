package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	InitializeValidators()
	os.Exit(m.Run())
}

// NormalizeText tests for StoryCreateRequest.

func TestStoryCreateRequest_NormalizeText(t *testing.T) {
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
	t.Run("decodes non-nil fields", func(t *testing.T) {
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
	Errors []ValidationError `json:"errors"`
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

func newTestContext(body string) (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(context.Background(), "POST", "/test", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

func TestBindAndValidate_ValidStoryRequest(t *testing.T) {
	body := `{"title":"Test Story","text":"Some content","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if !ok {
		t.Fatalf("expected true, got false; response: %s", w.Body.String())
	}
	if req.Title != "Test Story" {
		t.Errorf("Title = %q, want %q", req.Title, "Test Story")
	}
	if req.Text != "Some content" {
		t.Errorf("Text = %q, want %q", req.Text, "Some content")
	}
}

func TestBindAndValidate_MalformedJSON(t *testing.T) {
	c, w := newTestContext(`{invalid json}`)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false for malformed JSON")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
}

func TestBindAndValidate_EmptyBody(t *testing.T) {
	c, w := newTestContext("")

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false for empty body")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
}

func TestBindAndValidate_TypeMismatch(t *testing.T) {
	body := `{"name":"Test","max_stories_per_block":"five","pause_seconds":1.5}`
	c, w := newTestContext(body)

	var req StationRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false for type mismatch")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
}

func TestBindAndValidate_ValidationFailure_MissingRequired(t *testing.T) {
	body := `{"text":"Some content","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false when required 'title' is missing")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
	assertValidationError(t, w, "Title", "required")
}

func TestBindAndValidate_ValidationFailure_NotBlank(t *testing.T) {
	body := `{"title":"   ","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false when title is whitespace-only (notblank)")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
	assertValidationError(t, w, "Title", "empty or whitespace")
}

func TestBindAndValidate_NormalizesEntitiesBeforeValidation(t *testing.T) {
	body := `{"title":"Tom &amp; Jerry","text":"Content &lt;here&gt;","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if !ok {
		t.Fatalf("expected true, got false; response: %s", w.Body.String())
	}
	if req.Title != "Tom & Jerry" {
		t.Errorf("Title = %q, want %q (entities should be decoded)", req.Title, "Tom & Jerry")
	}
	if req.Text != "Content <here>" {
		t.Errorf("Text = %q, want %q (entities should be decoded)", req.Text, "Content <here>")
	}
}

func TestBindAndValidate_NonNormalizerType(t *testing.T) {
	body := `{"name":"Test Station","max_stories_per_block":5,"pause_seconds":1.5}`
	c, w := newTestContext(body)

	var req StationRequest
	ok := BindAndValidate(c, &req)

	if !ok {
		t.Fatalf("expected true, got false; response: %s", w.Body.String())
	}
	if req.Name != "Test Station" {
		t.Errorf("Name = %q, want %q", req.Name, "Test Station")
	}
	if req.MaxStoriesPerBlock != 5 {
		t.Errorf("MaxStoriesPerBlock = %d, want 5", req.MaxStoriesPerBlock)
	}
}

func TestBindAndValidate_CustomValidator_StoryStatus(t *testing.T) {
	body := `{"title":"Test","text":"content","status":"invalid_status","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false for invalid story status")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
	assertValidationError(t, w, "Status", "must be one of")
}

func TestBindAndValidate_CustomValidator_DateFormat(t *testing.T) {
	body := `{"title":"Test","text":"content","start_date":"not-a-date","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false for invalid date format")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
	assertValidationError(t, w, "StartDate", "YYYY-MM-DD")
}

func TestBindAndValidate_MaxLengthCheckedAfterNormalization(t *testing.T) {
	// 496 chars + "&amp;" (5 encoded, 1 decoded) = 501 encoded, 497 decoded.
	// Must pass because max=500 applies to the decoded value.
	title := strings.Repeat("A", 496) + "&amp;"

	body := `{"title":"` + title + `","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if !ok {
		t.Fatalf("expected true (497 decoded chars <= 500), got false; response: %s", w.Body.String())
	}
	if len(req.Title) != 497 {
		t.Errorf("decoded Title length = %d, want 497", len(req.Title))
	}
}

func TestBindAndValidate_MaxLengthRejectsAfterNormalization(t *testing.T) {
	// 500 chars + "&amp;" (5 encoded, 1 decoded) = 505 encoded, 501 decoded.
	// Must fail because decoded length exceeds max=500.
	title := strings.Repeat("A", 500) + "&amp;"

	body := `{"title":"` + title + `","text":"content","start_date":"2024-01-01","end_date":"2024-12-31"}`
	c, w := newTestContext(body)

	var req StoryCreateRequest
	ok := BindAndValidate(c, &req)

	if ok {
		t.Fatal("expected false (501 decoded chars > 500)")
	}
	if w.Code != 422 {
		t.Errorf("status = %d, want 422", w.Code)
	}
	assertValidationError(t, w, "Title", "cannot exceed 500")
}

func TestBindAndValidate_UpdateRequest_MaxLengthAfterNormalization(t *testing.T) {
	// StoryUpdateRequest uses pointer fields — verify the same boundary via the update path.
	t.Run("passes when decoded length within limit", func(t *testing.T) {
		title := strings.Repeat("A", 496) + "&amp;"
		body := `{"title":"` + title + `"}`
		c, w := newTestContext(body)

		var req StoryUpdateRequest
		ok := BindAndValidate(c, &req)

		if !ok {
			t.Fatalf("expected true (497 decoded chars <= 500), got false; response: %s", w.Body.String())
		}
		if req.Title == nil || len(*req.Title) != 497 {
			t.Errorf("decoded Title length = %v, want 497", req.Title)
		}
	})

	t.Run("rejects when decoded length exceeds limit", func(t *testing.T) {
		title := strings.Repeat("A", 500) + "&amp;"
		body := `{"title":"` + title + `"}`
		c, w := newTestContext(body)

		var req StoryUpdateRequest
		ok := BindAndValidate(c, &req)

		if ok {
			t.Fatal("expected false (501 decoded chars > 500)")
		}
		if w.Code != 422 {
			t.Errorf("status = %d, want 422", w.Code)
		}
		assertValidationError(t, w, "Title", "cannot exceed 500")
	})
}

// Double-encoded entity pipeline documenting the full write-read decode behavior.

func TestDoubleEncodedEntities_FullPipeline(t *testing.T) {
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

	// Step 2: Simulate DB round-trip — AfterFind decodes again on read
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
