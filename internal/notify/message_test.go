package notify

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestAlertSendsAfterParentDeadline(t *testing.T) {
	now := time.Now()
	svc, mailer := newTestService(&now)
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(-time.Second))
	defer cancel()
	svc.Alert(ctx, Event{Key: "scheduler:cleanup", Summary: "Cleanup deadline exceeded", Details: ctx.Err().Error()})
	svc.Close()
	if mailer.count() != 1 || mailer.messages[0].ctxErr != nil {
		t.Fatalf("messages = %+v, want one alert sent with a live context despite the expired parent", mailer.messages)
	}
}

func TestSendAddressesConfiguredRecipients(t *testing.T) {
	now := time.Now()
	svc, mailer := newTestService(&now)
	if err := svc.SendCritical(t.Context(), Event{Key: "process:exit", Summary: "Stopping"}); err != nil {
		t.Fatalf("SendCritical: %v", err)
	}
	got := mailer.messages[0]
	if !slices.Equal(got.recipients, []string{"one@example.com", "two@example.com"}) || got.subject != "[ALERT] Stopping - Babbel" || !strings.HasPrefix(got.body, "Stopping\n\n") || got.html {
		t.Fatalf("message = %+v, want a plain text subject and body addressed to both configured recipients", got)
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
