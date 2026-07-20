package notify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGraphClientSendMail(t *testing.T) {
	var request graphMailRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/users/sender@example.com/sendMail") {
			t.Errorf("path = %s, want sender mailbox sendMail path", r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := &GraphClient{fromAddress: "sender@example.com", baseURL: server.URL, httpClient: server.Client()}
	if err := client.SendMail(t.Context(), []string{"one@example.com", "two@example.com"}, "subject", "body"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if request.Message.Subject != "subject" || request.Message.Body.Content != "body" {
		t.Fatalf("unexpected message payload: %+v", request.Message)
	}
	if got := len(request.Message.ToRecipients); got != 2 {
		t.Fatalf("recipient count = %d, want 2", got)
	}
}

func TestGraphClientRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		cancel()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := &GraphClient{fromAddress: "sender@example.com", baseURL: server.URL, httpClient: server.Client()}
	err := client.SendMail(ctx, []string{"admin@example.com"}, "subject", "body")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendMail error = %v, want context cancellation", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want 1", requests)
	}
}

func TestGraphClientRejectsEmptyRecipients(t *testing.T) {
	client := &GraphClient{}
	err := client.SendMail(t.Context(), nil, "subject", "body")
	if err == nil || !strings.Contains(err.Error(), "no recipients") {
		t.Fatalf("SendMail error = %v, want no recipients", err)
	}
}

func TestGraphClientRetryAfterIsCapped(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "90")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	var waits []time.Duration
	client := &GraphClient{
		fromAddress: "sender@example.com",
		baseURL:     server.URL,
		httpClient:  server.Client(),
		wait: func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			return nil
		},
	}
	if err := client.SendMail(t.Context(), []string{"admin@example.com"}, "subject", "body"); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(waits) != 1 || waits[0] != maxRetryWait {
		t.Fatalf("retry waits = %v, want [%s]", waits, maxRetryWait)
	}
}

func TestGraphClientServerErrorsExhaustRetries(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	var waits []time.Duration
	client := &GraphClient{
		fromAddress: "sender@example.com",
		baseURL:     server.URL,
		httpClient:  server.Client(),
		wait: func(_ context.Context, delay time.Duration) error {
			waits = append(waits, delay)
			return nil
		},
	}
	err := client.SendMail(t.Context(), []string{"admin@example.com"}, "subject", "body")
	if err == nil || !strings.Contains(err.Error(), "retries exhausted") || !strings.Contains(err.Error(), "503") {
		t.Fatalf("SendMail error = %v, want exhausted 503 error", err)
	}
	if requests != maxRetries+1 {
		t.Fatalf("requests = %d, want %d", requests, maxRetries+1)
	}
	if len(waits) != maxRetries {
		t.Fatalf("retry waits = %v, want %d waits", waits, maxRetries)
	}
	for _, delay := range waits {
		if delay <= 0 || delay > maxRetryWait {
			t.Fatalf("retry delay = %s, want within (0, %s]", delay, maxRetryWait)
		}
	}
}
