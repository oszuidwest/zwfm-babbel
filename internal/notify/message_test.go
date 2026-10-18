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

func TestFormatMessageBoundsDetails(t *testing.T) {
	t.Parallel()
	at := time.Now()
	event := Event{Summary: "Failure", Key: "key"}
	_, header := formatMessage("[ALERT]", event, at, 1)
	for _, details := range []string{strings.Repeat("x", 100000), "x" + strings.Repeat("😀", 25000)} {
		t.Run(fmt.Sprintf("first rune %q", []rune(details)[0]), func(t *testing.T) {
			event.Details = details
			_, body := formatMessage("[ALERT]", event, at, 1)
			kept := strings.TrimSuffix(strings.TrimPrefix(body, header+"\n\n"), "\n[truncated]")
			if len(kept) > maxDetailsBytes || len(kept) < maxDetailsBytes-3 || !utf8.ValidString(body) || !strings.HasSuffix(body, "\n[truncated]") {
				t.Fatalf("kept %d detail bytes, valid UTF-8 = %v; want a marked prefix of up to %d bytes", len(kept), utf8.ValidString(body), maxDetailsBytes)
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
