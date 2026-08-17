package handlers

import "testing"

func TestValidByteRange(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		size   int64
		want   bool
	}{
		{name: "omitted", size: 100, want: true},
		{name: "bounded", header: "bytes=0-9", size: 100, want: true},
		{name: "open ended", header: "bytes=10-", size: 100, want: true},
		{name: "suffix", header: "bytes=-10", size: 100, want: true},
		{name: "multiple", header: "bytes=0-9, 90-99", size: 100, want: true},
		{name: "one overlapping range", header: "bytes=0-9, 200-300", size: 100, want: true},
		{name: "wrong unit", header: "items=0-9", size: 100, want: false},
		{name: "malformed", header: "bytes=abc", size: 100, want: false},
		{name: "reversed", header: "bytes=10-5", size: 100, want: false},
		{name: "no overlap", header: "bytes=100-200", size: 100, want: false},
		{name: "empty file ignores no overlap", header: "bytes=1-2", size: 0, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := validByteRange(tt.header, tt.size); got != tt.want {
				t.Fatalf("validByteRange(%q, %d) = %v, want %v", tt.header, tt.size, got, tt.want)
			}
		})
	}
}
