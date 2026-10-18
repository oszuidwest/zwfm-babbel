package logger

// MaxValueBytes bounds the prefix of an untrusted value included in logs.
const MaxValueBytes = 1024

// TruncateValue bounds an untrusted log value and marks a shortened value.
func TruncateValue(value string) string {
	if len(value) <= MaxValueBytes {
		return value
	}
	return value[:MaxValueBytes] + " (truncated)"
}
