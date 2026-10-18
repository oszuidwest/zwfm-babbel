package logger

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateValue(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct{ value, want string }{
		"within the limit": {strings.Repeat("x", MaxValueBytes), strings.Repeat("x", MaxValueBytes)},
		"over the limit":   {strings.Repeat("x", MaxValueBytes+1), strings.Repeat("x", MaxValueBytes) + " (truncated)"},
		"split rune":       {strings.Repeat("x", MaxValueBytes-1) + "€", strings.Repeat("x", MaxValueBytes-1) + " (truncated)"},
	} {
		if got := TruncateValue(tt.value); got != tt.want || !utf8.ValidString(got) {
			t.Errorf("%s: TruncateValue = %q, want %q", name, got, tt.want)
		}
	}
}
