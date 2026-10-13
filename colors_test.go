package main

import (
	"strings"
	"testing"
)

// Regression test for the subtle part of the coloring scheme: padding must
// happen BEFORE wrapping in ANSI codes, or the invisible escape bytes count
// toward the width and misalign columns. Checked with color forced both on
// and off, since colorEnabled is normally decided once from the terminal.
func TestColorizePaddedVisibleWidth(t *testing.T) {
	old := colorEnabled
	defer func() { colorEnabled = old }()

	for _, enabled := range []bool{true, false} {
		colorEnabled = enabled
		s := colorizePadded(ansiRed, "NEWLY_DROPPED", 20)
		visible := strings.ReplaceAll(strings.ReplaceAll(s, ansiRed, ""), ansiReset, "")

		if len(visible) != 20 {
			t.Fatalf("colorEnabled=%v: visible width = %d, want 20 (s=%q)", enabled, len(visible), s)
		}
		if strings.TrimSpace(visible) != "NEWLY_DROPPED" {
			t.Fatalf("colorEnabled=%v: visible text = %q, want \"NEWLY_DROPPED\"", enabled, strings.TrimSpace(visible))
		}
		if enabled && !strings.Contains(s, ansiRed) {
			t.Fatalf("colorEnabled=true: expected ANSI code in output, got %q", s)
		}
		if !enabled && strings.Contains(s, "\033") {
			t.Fatalf("colorEnabled=false: expected no ANSI codes, got %q", s)
		}
	}
}

func TestChangeColorCoversEveryCategory(t *testing.T) {
	for _, change := range []string{"UNCHANGED", "NEWLY_DROPPED", "NEWLY_ALLOWED", "not simulated", "reply (skipped)"} {
		if changeColor(change) == "" {
			t.Fatalf("changeColor(%q) returned no color", change)
		}
	}
}
