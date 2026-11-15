package main

import (
	"os"
	"regexp"
	"testing"
)

// TestCiliumPinsAgree guards the three places the pinned Cilium version
// has to be written down by hand: go.mod (the engine actually compiled
// in), pinnedCiliumVersion (what version/skew/compat logic believes it
// is — go.mod isn't readable at runtime, see globals.go) and lab-up.sh's
// CILIUM_VERSION (what the lab cluster runs). Nothing else ties them
// together: bumping only go.mod — by hand, or a dependency bot's PR —
// still builds and passes every other test, while the binary misreports
// its engine version, the skew warning compares against the wrong
// number, and the lab validates against a different Cilium than the one
// embedded.
func TestCiliumPinsAgree(t *testing.T) {
	gomod := mustMatch(t, "go.mod", `(?m)^\s*github\.com/cilium/cilium v(\S+)\s*$`)
	lab := mustMatch(t, "lab/scripts/lab-up.sh", `(?m)^CILIUM_VERSION="([^"]+)"`)

	if gomod != pinnedCiliumVersion {
		t.Errorf("go.mod pins github.com/cilium/cilium v%s but globals.go's pinnedCiliumVersion is %q — run `mise run bump-cilium v%s` or fix by hand", gomod, pinnedCiliumVersion, gomod)
	}
	if lab != pinnedCiliumVersion {
		t.Errorf("lab/scripts/lab-up.sh's CILIUM_VERSION is %q but pinnedCiliumVersion is %q", lab, pinnedCiliumVersion)
	}
}

func mustMatch(t *testing.T, path, pattern string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	m := regexp.MustCompile(pattern).FindSubmatch(b)
	if m == nil {
		t.Fatalf("%s: no match for %s — did its format change?", path, pattern)
	}
	return string(m[1])
}
