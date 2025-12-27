// Package version provides version information for the application.
package version

// Build information variables are set via ldflags during the build process.
var (
	// Version is the semantic version of the application.
	Version = "dev"
	// Commit is the git commit hash of the build.
	Commit = "unknown"
	// BuildTime is the timestamp when the binary was built.
	BuildTime = "unknown"
)
