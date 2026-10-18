package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
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
	if contentType := w.Header().Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", contentType)
	}
	var resp problemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if want.field == "" {
		if len(resp.Errors) != 0 {
			t.Fatalf("errors = %+v, want no field errors", resp.Errors)
		}
		return
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("errors = %+v, want exactly one %s/%s error", resp.Errors, want.field, want.code)
	}
	e := resp.Errors[0]
	if e.Field != want.field || e.Code != want.code || e.Message == "" {
		t.Errorf("error = %+v, want %s/%s with a message", e, want.field, want.code)
	}
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
		{name: "invalid start date format", body: `{"title":"T","text":"x","start_date":"not-a-date","end_date":"2024-12-31"}`, want: bindExpect{status: 422, field: "start_date", code: "invalid_format"}},
		{name: "invalid end date format", body: `{"title":"T","text":"x","start_date":"2024-01-01","end_date":"not-a-date"}`, want: bindExpect{status: 422, field: "end_date", code: "invalid_format"}},
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
	t.Run("user empty email clears the stored address", func(t *testing.T) {
		t.Parallel()
		req := bindCase[UserUpdateRequest](t, `{"email":""}`, bindExpect{ok: true})
		if req.Email == nil || *req.Email != "" {
			t.Fatalf("Email = %v, want pointer to empty string", req.Email)
		}
	})
	t.Run("integer overflow", func(t *testing.T) {
		t.Parallel()
		bindCase[StoryUpdateRequest](t, `{"voice_id":9223372036854775808}`,
			bindExpect{status: 422, field: "voice_id", code: "out_of_range"})
	})
	t.Run("optional integer overflow", func(t *testing.T) {
		t.Parallel()
		bindCase[TTSSettingsUpdateRequest](t, `{"seed":9223372036854775808}`,
			bindExpect{status: 422, field: "seed", code: "out_of_range"})
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

func TestIDParam(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		wantID   int64
		wantOK   bool
		wantCode string
	}{
		{name: "positive integer", raw: "42", wantID: 42, wantOK: true},
		{name: "non-integer", raw: "abc", wantCode: "invalid_format"},
		{name: "zero", raw: "0", wantCode: "out_of_range"},
		{name: "negative", raw: "-1", wantCode: "out_of_range"},
		{name: "overflow", raw: "9223372036854775808", wantCode: "out_of_range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, "")
			c.Params = gin.Params{{Key: "id", Value: tt.raw}}
			got, ok := IDParam(c)
			if ok != tt.wantOK || got != tt.wantID {
				t.Fatalf("IDParam(%q) = %d, %v; want %d, %v", tt.raw, got, ok, tt.wantID, tt.wantOK)
			}
			if !tt.wantOK {
				checkBindResult(t, w, false, bindExpect{status: 422, field: "id", code: tt.wantCode})
			}
		})
	}
}

func TestSaveAudioUpload_ReadTimeout(t *testing.T) {
	tempDir := t.TempDir()
	router := gin.New()
	router.POST("/upload", func(c *gin.Context) {
		if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
			t.Error(err)
			return
		}
		if _, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "upload_timeout_test"); ok {
			_ = cleanup()
			t.Error("stalled upload succeeded")
		}
	})
	server := httptest.NewServer(router)
	defer server.Close()

	// Send a partial file and never complete the body.
	body, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	go func() {
		_, _ = io.WriteString(writer, "--boundary\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"clip.wav\"\r\n\r\naudio")
	}()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	client := server.Client()
	client.Timeout = 5 * time.Second
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var problem ProblemDetail
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusRequestTimeout || problem.Status != http.StatusRequestTimeout || problem.Type != ProblemTypeRequestTimeout {
		t.Fatalf("response = %d, %+v; want 408 request-timeout", response.StatusCode, problem)
	}
	if len(problem.Errors) != 0 {
		t.Errorf("errors = %+v, want none so the read error stays private", problem.Errors)
	}
	if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", got)
	}
}

func TestSaveAudioUpload_StorageFailure(t *testing.T) {
	tempDir := filepath.Join(t.TempDir(), "missing")
	c, w := newAudioUploadContext(t, "audio", "clip.wav", strings.NewReader("audio bytes"))
	_, _, ok := SaveAudioUpload(c, tempDir, "audio", "upload_contract_test")
	checkBindResult(t, w, ok, bindExpect{status: 500})
	if strings.Contains(w.Body.String(), tempDir) {
		t.Fatalf("response exposes the temp path: %s", w.Body.String())
	}
}

func TestSaveAudioUpload(t *testing.T) {
	tests := []struct {
		name       string
		field      string
		filename   string
		wantOK     bool
		wantStatus int
		wantField  string
		wantCode   string
	}{
		{name: "missing file", field: "audio", wantStatus: 422, wantField: "audio", wantCode: "required"},
		{name: "unsupported extension", field: "audio", filename: "notes.txt", wantStatus: 422, wantField: "audio", wantCode: "unsupported"},
		{name: "valid audio", field: "audio", filename: "clip.WAV", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			if tt.filename != "" {
				part, err := writer.CreateFormFile(tt.field, tt.filename)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(part, "audio bytes"); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/upload", &body)
			c.Request.Header.Set("Content-Type", writer.FormDataContentType())

			path, cleanup, ok := SaveAudioUpload(c, t.TempDir(), tt.field, "upload_contract_test")
			if tt.wantOK {
				if !ok || cleanup == nil {
					t.Fatalf("SaveAudioUpload() = %q, %v, want success", path, ok)
				}
				t.Cleanup(func() {
					if err := cleanup(); err != nil {
						t.Errorf("cleanup: %v", err)
					}
				})
				// #nosec G304 -- path is created by SaveAudioUpload in the test temp directory.
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "audio bytes" {
					t.Fatalf("stored upload = %q, %v", data, err)
				}
				return
			}
			checkBindResult(t, w, ok, bindExpect{status: tt.wantStatus, field: tt.wantField, code: tt.wantCode})
		})
	}
}

func TestSaveAudioUpload_StreamsToSingleFile(t *testing.T) {
	for _, size := range []int64{1 << 20, 33 << 20, maxAudioUploadBytes} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			tempDir := t.TempDir()
			var read int64
			observed := false
			content := uploadReaderFunc(func(p []byte) (int, error) {
				if !observed && read >= size/2 {
					observed = true
					entries, err := os.ReadDir(tempDir)
					if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "story_42_") {
						t.Errorf("temp dir while reading = %v, %v; want only the destination file", entries, err)
					}
				}
				clear(p)
				read += int64(len(p))
				return len(p), nil
			})
			c, w := newAudioUploadContext(t, "audio", "../../news clip.MP3", io.LimitReader(content, size))
			path, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "story_42")
			if !ok {
				t.Fatalf("SaveAudioUpload() failed: %s", w.Body.String())
			}
			t.Cleanup(func() { _ = cleanup() })
			if !observed {
				t.Fatal("upload was not observed while reading")
			}
			if filepath.Ext(path) != ".mp3" {
				t.Fatalf("upload path = %s, want lowercased .mp3 extension", path)
			}
			info, err := os.Stat(path)
			if err != nil || info.Size() != size {
				t.Fatalf("stored upload = %v, %v; want %d bytes", info, err, size)
			}
			checkTempFileCount(t, tempDir, 1)
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			checkTempFileCount(t, tempDir, 0)
		})
	}
}

func TestSaveAudioUpload_RejectedUploadLeavesNoFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		size     int64
		want     bindExpect
	}{
		{name: "one byte over file limit", filename: "clip.wav", size: maxAudioUploadBytes + 1, want: bindExpect{status: 413}},
		{name: "unsupported", filename: "notes.txt", size: 33 << 20, want: bindExpect{status: 422, field: "jingle", code: "unsupported"}},
		// As with FormFile, the size check wins over the extension check.
		{name: "unsupported and too large", filename: "notes.txt", size: maxAudioUploadBytes + 1, want: bindExpect{status: 413}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			var read int64
			content := uploadReaderFunc(func(p []byte) (int, error) {
				read += int64(len(p))
				// The last read also catches FormFile's spill file past 32 MiB.
				if filepath.Ext(tt.filename) == ".txt" && read >= tt.size {
					checkTempFileCount(t, tempDir, 0)
				}
				clear(p)
				return len(p), nil
			})
			c, w := newAudioUploadContext(t, "jingle", tt.filename, io.LimitReader(content, tt.size))
			path, cleanup, ok := SaveAudioUpload(c, tempDir, "jingle", "upload_contract_test")
			checkBindResult(t, w, ok, tt.want)
			if path != "" || cleanup != nil {
				t.Fatalf("failed upload = %q, cleanup present: %v", path, cleanup != nil)
			}
			checkTempFileCount(t, tempDir, 0)
		})
	}
}

func TestSaveAudioUpload_InvalidMultipart(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, contentType, body string
	}{
		{name: "wrong content type", contentType: "application/json", body: "{}"},
		{name: "malformed content type", contentType: "multipart/form-data; boundary", body: "{}"},
		{name: "multipart mixed", contentType: "multipart/mixed; boundary=boundary", body: "--boundary--\r\n"},
		{name: "missing boundary", contentType: "multipart/form-data"},
		{name: "empty body", contentType: "multipart/form-data; boundary=boundary"},
		{name: "not multipart", contentType: "multipart/form-data; boundary=boundary", body: "garbage"},
		{name: "malformed part header", contentType: "multipart/form-data; boundary=boundary", body: "--boundary\r\ninvalid part\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, w := newTestContext(t, tt.body)
			c.Request.Header.Set("Content-Type", tt.contentType)
			_, _, ok := SaveAudioUpload(c, t.TempDir(), "audio", "upload_contract_test")
			checkBindResult(t, w, ok, bindExpect{status: 400, field: "request", code: "invalid_format"})
		})
	}
}

func TestSaveAudioUpload_SkippedPartsAreBounded(t *testing.T) {
	const otherHeader = "--boundary\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\n"
	const fileHeader = "\r\n--boundary\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"clip.wav\"\r\n\r\n"
	zeros := uploadReaderFunc(func(p []byte) (int, error) {
		clear(p)
		return len(p), nil
	})
	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "in skipped part", body: io.MultiReader(strings.NewReader(otherHeader), io.LimitReader(zeros, maxAudioUploadBytes+2<<20))},
		// The body limit is reached while the file is being stored.
		{name: "in file after skipped part", body: io.MultiReader(
			strings.NewReader(otherHeader), io.LimitReader(zeros, 2<<20),
			strings.NewReader(fileHeader), io.LimitReader(zeros, maxAudioUploadBytes),
		)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			c, w := newTestContext(t, "")
			c.Request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			c.Request.Body = io.NopCloser(tt.body)
			path, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "upload_contract_test")
			checkBindResult(t, w, ok, bindExpect{status: 413})
			if path != "" || cleanup != nil {
				t.Fatalf("failed upload = %q, cleanup present: %v", path, cleanup != nil)
			}
			checkTempFileCount(t, tempDir, 0)
		})
	}
}

func TestSaveAudioUpload_PartSelection(t *testing.T) {
	type uploadPart struct{ field, filename, content string }
	tests := []struct {
		name  string
		parts []uploadPart
		want  bindExpect
	}{
		{name: "only a non-file part", parts: []uploadPart{{"audio", "", "text"}}, want: bindExpect{status: 422, field: "audio", code: "required"}},
		{name: "only another file field", parts: []uploadPart{{"other", "clip.wav", "other bytes"}}, want: bindExpect{status: 422, field: "audio", code: "required"}},
		{name: "skip non-file and other field and keep first file", parts: []uploadPart{
			{"audio", "", "text"}, {"other", "notes.txt", "other bytes"},
			{"audio", "first.WAV", "first bytes"}, {"audio", "second.txt", "second bytes"},
		}, want: bindExpect{ok: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for _, entry := range tt.parts {
				var part io.Writer
				var err error
				if entry.filename == "" {
					part, err = writer.CreateFormField(entry.field)
				} else {
					part, err = writer.CreateFormFile(entry.field, entry.filename)
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(part, entry.content); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			c, w := newTestContext(t, body.String())
			c.Request.Header.Set("Content-Type", writer.FormDataContentType())
			path, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "upload_contract_test")
			checkBindResult(t, w, ok, tt.want)
			if ok {
				t.Cleanup(func() { _ = cleanup() })
				// #nosec G304 -- path is created by SaveAudioUpload in the test temp directory.
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "first bytes" {
					t.Fatalf("stored upload = %q, %v; want first file", data, err)
				}
				if err := cleanup(); err != nil {
					t.Fatal(err)
				}
			}
			checkTempFileCount(t, tempDir, 0)
		})
	}
}

func TestSaveAudioUpload_BodyReadFailure(t *testing.T) {
	const fileHeader = "--boundary\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"clip.wav\"\r\n\r\naudio"
	const unsupportedHeader = "--boundary\r\nContent-Disposition: form-data; name=\"audio\"; filename=\"notes.txt\"\r\n\r\ntext"
	const otherHeader = "--boundary\r\nContent-Disposition: form-data; name=\"other\"\r\n\r\ntext"
	tests := []struct {
		name   string
		prefix string
	}{
		{name: "before headers"},
		{name: "in file", prefix: fileHeader},
		{name: "in skipped part", prefix: otherHeader},
		{name: "after stored file", prefix: fileHeader + "\r\n" + otherHeader},
		// As with FormFile, read errors win over the extension check.
		{name: "after unsupported file", prefix: unsupportedHeader + "\r\n" + otherHeader},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, readErr := range []error{os.ErrDeadlineExceeded, io.ErrUnexpectedEOF} {
				t.Run(readErr.Error(), func(t *testing.T) {
					tempDir := t.TempDir()
					c, w := newTestContext(t, "")
					c.Request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
					c.Request.Body = io.NopCloser(io.MultiReader(strings.NewReader(tt.prefix), iotest.ErrReader(readErr)))
					path, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "upload_contract_test")
					want := bindExpect{status: 400, field: "request", code: "invalid_format"}
					if errors.Is(readErr, os.ErrDeadlineExceeded) {
						want = bindExpect{status: 408}
					}
					checkBindResult(t, w, ok, want)
					if path != "" || cleanup != nil {
						t.Fatalf("failed upload = %q, cleanup present: %v", path, cleanup != nil)
					}
					checkTempFileCount(t, tempDir, 0)
				})
			}
		})
	}
}

func TestSaveAudioUpload_PartLimit(t *testing.T) {
	for _, tt := range []struct {
		parts int
		want  bindExpect
	}{
		{parts: maxAudioUploadParts, want: bindExpect{ok: true}},
		{parts: maxAudioUploadParts + 1, want: bindExpect{status: 400, field: "request", code: "invalid_format"}},
	} {
		t.Run(fmt.Sprintf("%d parts", tt.parts), func(t *testing.T) {
			tempDir := t.TempDir()
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			if _, err := writer.CreateFormFile("audio", "clip.wav"); err != nil {
				t.Fatal(err)
			}
			for range tt.parts - 1 {
				if err := writer.WriteField("other", "text"); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			c, w := newTestContext(t, body.String())
			c.Request.Header.Set("Content-Type", writer.FormDataContentType())
			_, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "upload_contract_test")
			checkBindResult(t, w, ok, tt.want)
			if ok {
				if err := cleanup(); err != nil {
					t.Fatal(err)
				}
			}
			checkTempFileCount(t, tempDir, 0)
		})
	}
}

// newAudioUploadContext returns a context whose multipart body holds content as
// a file part for field, named filename. Only the multipart framing is held in
// memory.
func newAudioUploadContext(t *testing.T, field, filename string, content io.Reader) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if _, err := writer.CreateFormFile(field, filename); err != nil {
		t.Fatal(err)
	}
	header := body.String()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	c, w := newTestContext(t, "")
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())
	c.Request.Body = io.NopCloser(io.MultiReader(strings.NewReader(header), content, strings.NewReader(body.String()[len(header):])))
	return c, w
}

type uploadReaderFunc func([]byte) (int, error)

func (f uploadReaderFunc) Read(p []byte) (int, error) {
	return f(p)
}

// checkTempFileCount fails unless dir holds exactly want entries, so it also
// catches multipart spill files left beside an upload.
func checkTempFileCount(t *testing.T, dir string, want int) {
	t.Helper()
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != want {
		t.Fatalf("temp dir = %v, %v; want %d files", entries, err, want)
	}
}

func TestSaveAudioUpload_SameFilenameGetsOwnFile(t *testing.T) {
	tempDir := t.TempDir()
	save := func(content string) (string, func() error) {
		t.Helper()
		c, w := newAudioUploadContext(t, "audio", "news clip.MP3", strings.NewReader(content))
		path, cleanup, ok := SaveAudioUpload(c, tempDir, "audio", "story_42")
		if !ok {
			t.Fatalf("SaveAudioUpload() failed: %s", w.Body.String())
		}
		return path, cleanup
	}

	// Both requests hold their input before either finishes.
	firstPath, firstCleanup := save("first upload")
	secondPath, _ := save("second upload")
	if firstPath == secondPath {
		t.Fatalf("both uploads stored at %s", firstPath)
	}
	for _, path := range []string{firstPath, secondPath} {
		if filepath.Dir(path) != tempDir || !strings.HasPrefix(filepath.Base(path), "story_42_") || filepath.Ext(path) != ".mp3" {
			t.Fatalf("upload path = %s, want story_42_*.mp3 in %s", path, tempDir)
		}
	}

	// A failed request cleans up only its own input.
	if err := firstCleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(firstPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first upload after cleanup: %v, want removed", err)
	}
	// #nosec G304 -- path is created by SaveAudioUpload in the test temp directory.
	if data, err := os.ReadFile(secondPath); err != nil || string(data) != "second upload" {
		t.Fatalf("second upload = %q, %v; want its own content", data, err)
	}
}

func TestWriteTempFile_RemovesPartialOutput(t *testing.T) {
	tempDir := t.TempDir()
	if path, err := WriteTempFile(tempDir, failingReadCloser{}, "upload_*.wav"); err == nil {
		t.Fatalf("WriteTempFile() = %q, want read error", path)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("temp dir = %v, %v; want partial output removed", entries, err)
	}
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
