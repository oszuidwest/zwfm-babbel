package notify

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestAlertSendsAfterParentDeadline(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	now := time.Now()
	svc, _ := newTestService(&now)
	svc.mailer = &graphClient{fromAddress: "sender@example.com", baseURL: server.URL, httpClient: server.Client()}
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(-time.Second))
	defer cancel()
	svc.Alert(ctx, Event{Key: "scheduler:cleanup", Summary: "Cleanup deadline exceeded", Details: ctx.Err().Error()})
	svc.Close()
	if requests.Load() != 1 {
		t.Fatalf("Graph requests = %d, want an alert despite the expired parent", requests.Load())
	}
}

func TestFormatMessageBoundsBody(t *testing.T) {
	t.Parallel()
	for _, text := range []string{strings.Repeat("x", 100000), strings.Repeat("😀", 25000)} {
		t.Run(fmt.Sprintf("first rune %q", []rune(text)[0]), func(t *testing.T) {
			subject, body := formatMessage("[ALERT]", Event{Summary: text, Key: text, Details: text}, time.Now(), 1000)
			if strings.ContainsAny(subject, "\r\n") {
				t.Fatalf("subject contains a line break: %q", subject)
			}
			if len(body) > maxMessageBytes || !utf8.ValidString(body) || !strings.HasSuffix(body, "\n[truncated]") {
				t.Fatalf("body size = %d, valid UTF-8 = %v, want bounded marked body", len(body), utf8.ValidString(body))
			}
		})
	}
}

func TestFormatMessageExactBodyBudget(t *testing.T) {
	t.Parallel()
	at := time.Now()
	event := Event{Summary: "Failure", Key: "key"}
	_, header := formatMessage("[ALERT]", event, at, 1)
	budget := maxMessageBytes - len(header) - len("\n\n")
	for _, extra := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(extra), func(t *testing.T) {
			event.Details = strings.Repeat("x", budget+extra)
			_, body := formatMessage("[ALERT]", event, at, 1)
			if len(body) != min(maxMessageBytes, maxMessageBytes+extra) || strings.Contains(body, "[truncated]") != (extra > 0) {
				t.Fatalf("extra = %d, length = %d, marked = %v", extra, len(body), strings.Contains(body, "[truncated]"))
			}
		})
	}
}

func TestFormatMessageKeepsNormalDetails(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	subject, body := formatMessage("[ALERT]", Event{Summary: "Failure", Key: "test:key", Details: "Cause"}, at, 3)
	if subject != "[ALERT] Failure - Babbel" || body != "Failure\n\nTimestamp: 2026-10-18T12:00:00Z\nAlert key: test:key\nOccurrences in current window: 3\n\nCause" {
		t.Fatalf("subject = %q, body = %q", subject, body)
	}
}
