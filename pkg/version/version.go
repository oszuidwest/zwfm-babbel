// Package version provides version information for the application.
package version

import "fmt"

// Build information variables are set via ldflags during the build process.
var (
	// Version is the semantic version of the application.
	Version = "dev"
	// Commit is the git commit hash of the build.
	Commit = "unknown"
	// BuildTime is the timestamp when the binary was built.
	BuildTime = "unknown"
)

// String returns a formatted version string with all version information.
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildTime)
}
