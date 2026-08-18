package handlers

import (
	"net/http"
	"net/http/httptest"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acceptsJSON(tt.header); got != tt.want {
				t.Errorf("acceptsJSON(%q) = %t, want %t", tt.header, got, tt.want)
			}
		})
	}
}
