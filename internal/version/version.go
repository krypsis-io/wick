// Package version holds build-time version information injected via ldflags.
package version

// Set by goreleaser ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
