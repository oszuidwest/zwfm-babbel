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

// BindJSON tests.

// problemResponse is the subset of the RFC 9457 response we assert on.
type problemResponse struct {
	Errors []apperrors.FieldError `json:"errors"`
}

func TestProblemDetailAlwaysIncludesDetail(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(NewProblemDetail("about:blank", "Error", 500, ""))
	if err != nil {
		t.Fatalf("marshal problem: %v", err)
	}
	if !strings.Contains(string(body), `"detail":""`) {
		t.Fatalf("problem JSON = %s, want required detail member", body)
	}
}

func TestFieldErrorJSON(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(apperrors.FieldError{Field: "title", Code: apperrors.CodeRequired, Message: "is required"})
	if err != nil {
		t.Fatalf("marshal field error: %v", err)
	}
	if got, want := string(body), `{"field":"title","code":"required","message":"is required"}`; got != want {
		t.Fatalf("field error JSON = %s, want %s", got, want)
	}
}

func newTestContext(t *testing.T, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequestWithContext(t.Context(), "POST", "/test", bytes.NewBufferString(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

// bindExpect describes a successful bind (ok) or the status and the field
// error that the response must contain.
type bindExpect struct {
	ok     bool
	status int
	field  string
	code   string
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
	if w.Code != want.status {
		t.Errorf("status = %d, want %d; response: %s", w.Code, want.status, w.Body.String())
	}
	if want.status == 413 {
		return
	}
	var resp problemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	for _, e := range resp.Errors {
		if e.Field == want.field && e.Code == want.code && e.Message != "" {
			return
		}
	}
	t.Errorf("expected field error %s/%s, got errors: %+v", want.field, want.code, resp.Errors)
}

func bindCase[T any](t *testing.T, body string, want bindExpect) *T {
	t.Helper()
	c, w := newTestContext(t, body)
	var req T
	ok := BindJSON(c, &req)
	checkBindResult(t, w, ok, want)
	return &req
}

func TestBindJSON_StoryCreateRequest(t *testing.T) {
	t.Parallel()

	// Boundary inputs: max=500 applies to the *decoded* value.
	// "A"*496 + "&amp;" = 501 encoded -> 497 decoded (allowed).
	// "A"*500 + "&amp;" = 505 encoded -> 501 decoded (rejected).
	titleAt497 := strings.Repeat("A", 496) + "&amp;"
	titleAt501 := strings.Repeat("A", 500) + "&amp;"
	const dates = `"start_date":"2024-01-01","end_date":"2024-12-31"`

	tests := []struct {
		name   string
		body   string
		want   bindExpect
		verify func(t *testing.T, req *StoryCreateRequest)
	}{
		{
			name: "valid request",
			body: `{"title":"Test Story","text":"Some content",` + dates + `}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if req.Title != "Test Story" || req.Text != "Some content" {
					t.Errorf("got Title=%q Text=%q", req.Title, req.Text)
				}
			},
		},
		{name: "malformed JSON", body: `{invalid json}`, want: bindExpect{status: 400, field: "request", code: "invalid_json"}},
		{name: "empty body", body: "", want: bindExpect{status: 400, field: "request", code: "required"}},
		{name: "whitespace body", body: " \n", want: bindExpect{status: 400, field: "request", code: "required"}},
		{name: "array root", body: `[]`, want: bindExpect{status: 400, field: "request", code: "invalid_type"}},
		{name: "null root", body: `null`, want: bindExpect{status: 400, field: "request", code: "invalid_type"}},
		{name: "trailing content", body: `{"title":"T","text":"x",` + dates + `}{}`, want: bindExpect{status: 400, field: "request", code: "invalid_json"}},
		{name: "unknown field", body: `{"title":"T","text":"x","bogus":1,` + dates + `}`, want: bindExpect{status: 400, field: "bogus", code: "unknown_field"}},
		{name: "field names are case-sensitive", body: `{"Title":"T","text":"x",` + dates + `}`, want: bindExpect{status: 400, field: "Title", code: "unknown_field"}},
		{name: "duplicate field", body: `{"title":"T","title":"U","text":"x",` + dates + `}`, want: bindExpect{status: 400, field: "title", code: "duplicate"}},
		{name: "wrong JSON type", body: `{"title":1,"text":"x",` + dates + `}`, want: bindExpect{status: 400, field: "title", code: "invalid_type"}},
		{name: "fractional weekdays", body: `{"title":"T","text":"x","weekdays":1.5,` + dates + `}`, want: bindExpect{status: 400, field: "weekdays", code: "invalid_type"}},
		{name: "missing required title", body: `{"text":"Some content",` + dates + `}`, want: bindExpect{status: 422, field: "title", code: "required"}},
		{name: "whitespace-only title", body: `{"title":"   ","text":"content",` + dates + `}`, want: bindExpect{status: 422, field: "title", code: "blank"}},
		{
			name: "entities decoded before validation",
			body: `{"title":"Tom &amp; Jerry","text":"Content &lt;here&gt;",` + dates + `}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if req.Title != "Tom & Jerry" || req.Text != "Content <here>" {
					t.Errorf("entities not decoded: Title=%q Text=%q", req.Title, req.Text)
				}
			},
		},
		{name: "invalid story status", body: `{"title":"T","text":"x","status":"bogus",` + dates + `}`, want: bindExpect{status: 422, field: "status", code: "invalid_choice"}},
		{name: "invalid date format", body: `{"title":"T","text":"x","start_date":"not-a-date","end_date":"2024-12-31"}`, want: bindExpect{status: 422, field: "start_date", code: "invalid_format"}},
		{name: "weekdays above bitmask", body: `{"title":"T","text":"x","weekdays":128,` + dates + `}`, want: bindExpect{status: 422, field: "weekdays", code: "out_of_range"}},
		{name: "negative voice id", body: `{"title":"T","text":"x","voice_id":-1,` + dates + `}`, want: bindExpect{status: 422, field: "voice_id", code: "out_of_range"}},
		{
			name: "max length applies to decoded value (passes)",
			body: `{"title":"` + titleAt497 + `","text":"content",` + dates + `}`,
			want: bindExpect{ok: true},
			verify: func(t *testing.T, req *StoryCreateRequest) {
				if len(req.Title) != 497 {
					t.Errorf("decoded Title length = %d, want 497", len(req.Title))
				}
			},
		},
		{name: "max length applies to decoded value (rejects)", body: `{"title":"` + titleAt501 + `","text":"content",` + dates + `}`, want: bindExpect{status: 422, field: "title", code: "too_long"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := bindCase[StoryCreateRequest](t, tt.body, tt.want)
			if tt.want.ok && tt.verify != nil {
				tt.verify(t, req)
			}
		})
	}
}

func TestBindJSON_PartialUpdates(t *testing.T) {
	t.Parallel()

	titleAt501 := strings.Repeat("A", 500) + "&amp;"

	t.Run("story title max length", func(t *testing.T) {
		t.Parallel()
		bindCase[StoryUpdateRequest](t, `{"title":"`+titleAt501+`"}`, bindExpect{status: 422, field: "title", code: "too_long"})
	})
	t.Run("present empty date", func(t *testing.T) {
		t.Parallel()
		bindCase[StoryUpdateRequest](t, `{"start_date":""}`, bindExpect{status: 422, field: "start_date", code: "invalid_format"})
	})
	t.Run("absent date is skipped", func(t *testing.T) {
		t.Parallel()
		req := bindCase[StoryUpdateRequest](t, `{"title":"T"}`, bindExpect{ok: true})
		if req.StartDate != nil {
			t.Fatalf("StartDate = %v, want nil", req.StartDate)
		}
	})
	t.Run("user empty full name", func(t *testing.T) {
		t.Parallel()
		bindCase[UserUpdateRequest](t, `{"full_name":""}`, bindExpect{status: 422, field: "full_name", code: "blank"})
	})
	t.Run("user empty role", func(t *testing.T) {
		t.Parallel()
		bindCase[UserUpdateRequest](t, `{"role":""}`, bindExpect{status: 422, field: "role", code: "invalid_choice"})
	})
	t.Run("user empty password reaches the service", func(t *testing.T) {
		t.Parallel()
		req := bindCase[UserUpdateRequest](t, `{"password":""}`, bindExpect{ok: true})
		if req.Password == nil || *req.Password != "" {
			t.Fatalf("Password = %v, want pointer to empty string", req.Password)
		}
	})
	t.Run("voice null clears the ElevenLabs id", func(t *testing.T) {
		t.Parallel()
		req := bindCase[VoiceUpdateRequest](t, `{"elevenlabs_voice_id":null}`, bindExpect{ok: true})
		if !req.ElevenLabsVoiceID.Set || req.ElevenLabsVoiceID.Value != nil {
			t.Fatalf("ElevenLabsVoiceID = %+v, want set to null", req.ElevenLabsVoiceID)
		}
	})
	t.Run("optional wrong type reports its path", func(t *testing.T) {
		t.Parallel()
		bindCase[TTSSettingsUpdateRequest](t, `{"seed":"x"}`, bindExpect{status: 400, field: "seed", code: "invalid_type"})
	})
}

func TestBindJSON_Paths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bindExpect
	}{
		{name: "missing rules", body: `{}`, want: bindExpect{status: 422, field: "rules", code: "required"}},
		{name: "null rules", body: `{"rules":null}`, want: bindExpect{status: 422, field: "rules", code: "required"}},
		{name: "unknown member in array element", body: `{"rules":[{"string_to_replace":"a","ipa":"b"},{"alias":"c"}]}`, want: bindExpect{status: 400, field: "rules[1].alias", code: "unknown_field"}},
		{name: "wrong type in array element", body: `{"rules":[{"string_to_replace":"a","ipa":5}]}`, want: bindExpect{status: 400, field: "rules[0].ipa", code: "invalid_type"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bindCase[PronunciationRulesUpdateRequest](t, tt.body, tt.want)
		})
	}

	t.Run("anonymous request struct", func(t *testing.T) {
		t.Parallel()
		bindCase[struct {
			Status *string `json:"status" binding:"omitempty,oneof=draft active expired"`
		}](t, `{"status":"bogus"}`, bindExpect{status: 422, field: "status", code: "invalid_choice"})
	})
}

func TestBindJSON_StationRequests(t *testing.T) {
	t.Parallel()

	t.Run("valid non-normalizer type", func(t *testing.T) {
		t.Parallel()
		req := bindCase[StationRequest](t, `{"name":"Test Station","max_stories_per_block":5,"pause_seconds":1.5}`, bindExpect{ok: true})
		if req.Name != "Test Station" || req.MaxStoriesPerBlock == nil || *req.MaxStoriesPerBlock != 5 {
			t.Errorf("got Name=%q MaxStoriesPerBlock=%v", req.Name, req.MaxStoriesPerBlock)
		}
	})
	t.Run("type mismatch", func(t *testing.T) {
		t.Parallel()
		bindCase[StationRequest](t, `{"name":"Test","max_stories_per_block":"five"}`, bindExpect{status: 400, field: "max_stories_per_block", code: "invalid_type"})
	})
	t.Run("missing max stories per block", func(t *testing.T) {
		t.Parallel()
		bindCase[StationRequest](t, `{"name":"Test"}`, bindExpect{status: 422, field: "max_stories_per_block", code: "required"})
	})
	t.Run("missing station id", func(t *testing.T) {
		t.Parallel()
		bindCase[StationVoiceRequest](t, `{"voice_id":1}`, bindExpect{status: 422, field: "station_id", code: "required"})
	})
	t.Run("zero station id", func(t *testing.T) {
		t.Parallel()
		bindCase[StationVoiceRequest](t, `{"station_id":0,"voice_id":1}`, bindExpect{status: 422, field: "station_id", code: "out_of_range"})
	})
	t.Run("oversized body", func(t *testing.T) {
		t.Parallel()
		body := `{"name":"` + strings.Repeat("a", int(maxJSONRequestBodyBytes)+1) + `"}`
		bindCase[StationRequest](t, body, bindExpect{status: 413})
	})
	t.Run("oversized trailing whitespace", func(t *testing.T) {
		t.Parallel()
		body := `{"name":"Test","max_stories_per_block":5}` + strings.Repeat(" ", int(maxJSONRequestBodyBytes))
		bindCase[StationRequest](t, body, bindExpect{status: 413})
	})
}

func TestBindOptionalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bindExpect
	}{
		{name: "empty body is accepted", body: "", want: bindExpect{ok: true}},
		{name: "whitespace body is accepted", body: " \n\t ", want: bindExpect{ok: true}},
		{name: "empty object is accepted", body: `{}`, want: bindExpect{ok: true}},
		{name: "unknown member is rejected", body: `{"date":"2026-05-23"}`, want: bindExpect{status: 400, field: "date", code: "unknown_field"}},
		{name: "malformed json is rejected", body: `{invalid json}`, want: bindExpect{status: 400, field: "request", code: "invalid_json"}},
		{name: "oversized body is rejected", body: strings.Repeat("a", int(maxJSONRequestBodyBytes)+1), want: bindExpect{status: 413}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, tt.body)
			var req struct{}
			ok := BindOptionalJSON(c, &req)
			checkBindResult(t, w, ok, tt.want)
		})
	}
}

func TestBindJSON_ReadFailure(t *testing.T) {
	t.Parallel()
	c, w := newTestContext(t, "")
	c.Request.Body = failingReadCloser{}

	var req struct{}
	ok := BindOptionalJSON(c, &req)
	checkBindResult(t, w, ok, bindExpect{status: 400, field: "request", code: "invalid_json"})
}

func TestRequireAnyField(t *testing.T) {
	t.Parallel()

	c, w := newTestContext(t, "")
	if RequireAnyField(c, StoryUpdateRequest{}) {
		t.Fatal("RequireAnyField(empty) = true, want false")
	}
	checkBindResult(t, w, false, bindExpect{status: 422, field: "request", code: "empty_update"})
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
	//   Input -> NormalizeText (decode #1) -> stored in DB -> AfterFind (decode #2) -> output.

	// Step 1: NormalizeText decodes once on input.
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

	// Step 2: simulate a DB round-trip; AfterFind decodes again on read.
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
