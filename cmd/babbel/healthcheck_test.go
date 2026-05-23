package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunHealthcheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    bool
	}{
		{name: "ok", statusCode: http.StatusOK},
		{name: "bad request", statusCode: http.StatusBadRequest, wantErr: true},
		{name: "not found", statusCode: http.StatusNotFound, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			err := runHealthcheck(context.Background(), srv.URL)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunHealthcheckRequiresURL(t *testing.T) {
	t.Parallel()

	if err := runHealthcheck(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}
