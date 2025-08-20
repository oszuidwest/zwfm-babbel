// Package version provides version information for the application.
package version

// Build information variables are set via ldflags during the build process.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)
