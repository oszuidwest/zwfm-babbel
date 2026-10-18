package logger

import "strings"

// MaxValueBytes bounds the prefix of an untrusted value included in logs.
const MaxValueBytes = 1024

// TruncateValue bounds an untrusted log value and marks a shortened value.
func TruncateValue(value string) string {
	if len(value) <= MaxValueBytes {
		return value
	}
	// Drop invalid UTF-8, such as a rune split by the cut, from the prefix.
	return strings.ToValidUTF8(value[:MaxValueBytes], "") + " (truncated)"
}
