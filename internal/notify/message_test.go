package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestFormatMessageBoundsBody(t *testing.T) {
	t.Parallel()
	for _, text := range []string{strings.Repeat("x", 100000), strings.Repeat("😀", 25000)} {
		t.Run(fmt.Sprintf("first rune %q", []rune(text)[0]), func(t *testing.T) {
			_, body := formatMessage("[ALERT]", Event{Summary: text, Key: text, Details: text}, time.Now(), 1000)
			if len(body) > maxMessageBytes || !utf8.ValidString(body) || !strings.HasSuffix(body, "\n[truncated]") {
				t.Fatalf("body size = %d, valid UTF-8 = %v, want bounded marked body", len(body), utf8.ValidString(body))
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
