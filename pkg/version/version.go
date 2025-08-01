package version

import (
	"time"
)

// Build information (set via ldflags during build)
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// UserAgent returns the User-Agent string for HTTP requests
func UserAgent() string {
	return "babbel/" + Version
}

// GetBuildYear returns the year from the build time
func GetBuildYear() string {
	if BuildTime == "unknown" {
		return time.Now().Format("2006")
	}
	// Try to parse the build time
	t, err := time.Parse(time.RFC3339, BuildTime)
	if err != nil {
		// If parsing fails, try other common formats
		t, err = time.Parse("2006-01-02T15:04:05Z", BuildTime)
		if err != nil {
			// Fall back to current year
			return time.Now().Format("2006")
		}
	}
	return t.Format("2006")
}