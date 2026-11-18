package main

import (
	"os"
	"strings"
	"testing"
)

func TestProbeFlagsInShellCompletions(t *testing.T) {
	for _, path := range []string{"completions/guardbee.bash", "completions/guardbee.fish", "completions/_guardbee"} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"enable-probes", "probe-image"} {
			if !strings.Contains(string(contents), flag) {
				t.Errorf("%s missing %s", path, flag)
			}
		}
	}
}
