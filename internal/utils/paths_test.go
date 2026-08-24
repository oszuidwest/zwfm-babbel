package utils

import (
	"testing"
	"time"
)

func TestBulletinFilenameIncludesSubsecondPrecision(t *testing.T) {
	t.Parallel()

	first := BulletinFilename(7, time.Date(2026, 8, 18, 12, 30, 1, 1, time.UTC))
	second := BulletinFilename(7, time.Date(2026, 8, 18, 12, 30, 1, 2, time.UTC))
	if first == second {
		t.Fatalf("BulletinFilename() produced collision %q", first)
	}
}
