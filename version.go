package main

import "fmt"

// version is set at build time via -ldflags "-X main.version=...":
//   - mise.toml's "build" task sets it to "dev-<short-sha>" (plus "-dirty"
//     if the working tree has uncommitted changes), read from the local
//     git checkout at build time — never at runtime, so the binary itself
//     never needs git installed to report its own version.
//   - .github/workflows/release.yml sets it to the published release's own
//     tag instead (e.g. "v0.3.0").
// Plain `go build` (no ldflags) leaves it at this fallback, which is an
// honest answer for that case too: an ad-hoc build with no version wired in.
var version = "dev-unknown"

func runVersion(args []string) {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Printf("Usage: %s version\n\nPrint the version this binary was built from.\n", binName)
			return
		}
	}
	fmt.Printf("%s %s\n", binName, version)
}
