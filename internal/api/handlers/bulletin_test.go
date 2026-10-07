package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGenerateBulletinCombinesAcceptHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/api/v1/stations/invalid/bulletins",
		nil,
	)
	context.Request.Header.Add("Accept", "text/html")
	context.Request.Header.Add("Accept", gin.MIMEJSON)
	context.Params = gin.Params{{Key: "id", Value: "invalid"}}

	(&Handlers{}).GenerateBulletin(context)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("GenerateBulletin() status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestAcceptsJSON(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{name: "missing header", want: true},
		{name: "exact media type", header: "application/json", want: true},
		{name: "positive quality", header: "application/json;q=0.5", want: true},
		{name: "exact zero quality", header: "application/json;q=0"},
		{name: "wildcard zero quality", header: "*/*;q=0"},
		{name: "unsupported media type", header: "audio/wav"},
		{
			name:   "exact exclusion overrides acceptable wildcard",
			header: "application/json;q=0, */*;q=1",
		},
		{
			name:   "type exclusion overrides acceptable wildcard",
			header: "application/*;q=0, */*;q=1",
		},
		{
			name:   "highest quality wins for equal specificity",
			header: "application/json;q=0, application/json;q=0.5",
			want:   true,
		},
		{name: "malformed quality", header: "application/json;q=invalid"},
		{name: "exponent quality", header: "application/json;q=1e-1"},
		{name: "leading plus quality", header: "application/json;q=+0.5"},
		{name: "excessive quality precision", header: "application/json;q=0.0001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acceptsJSON(tt.header); got != tt.want {
				t.Errorf("acceptsJSON(%q) = %t, want %t", tt.header, got, tt.want)
			}
		})
	}
}

func TestGenerateBulletinRejectsDate(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "valid date", body: `{"date":"2026-10-07"}`},
		{name: "empty date", body: `{"date":""}`},
		{name: "null date", body: `{"date":null}`},
		{name: "numeric date", body: `{"date":123}`},
		{name: "object date", body: `{"date":{}}`},
		{name: "case insensitive date", body: `{"Date":"2026-10-07"}`},
		{name: "duplicate date ending in null", body: `{"date":"2026-10-07","date":null}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodPost,
				"/api/v1/stations/1/bulletins", strings.NewReader(test.body))
			c.Params = gin.Params{{Key: "id", Value: "1"}}

			(&Handlers{}).GenerateBulletin(c)

			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body = %s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type = %q, want application/problem+json", got)
			}
			problem := decodeProblem(t, recorder)
			if len(problem.Errors) != 1 || problem.Errors[0].Field != "date" {
				t.Fatalf("errors = %+v, want date validation error", problem.Errors)
			}
		})
	}
}
