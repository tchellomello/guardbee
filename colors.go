package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// colorEnabled is decided once at startup: only color a real terminal, and
// never when NO_COLOR is set (https://no-color.org) — piping to a file or a
// script shouldn't fill up with escape codes.
var colorEnabled = os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiGray   = "\033[90m"
)

// colorize wraps s in the given ANSI code, or returns it unchanged when
// coloring is disabled. Callers should pad/format s to its final visible
// width BEFORE calling this — escape codes count toward Go's %-Ns width
// calculation, which would otherwise misalign columns.
func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

// changeColor maps a verdict's change classification to its color, kept
// consistent across the per-row output, the summary line, and the legend so
// a reader can pattern-match by color alone.
func changeColor(change string) string {
	switch change {
	case "NEWLY_DROPPED":
		return ansiRed
	case "NEWLY_ALLOWED":
		return ansiYellow
	case "UNCHANGED":
		return ansiGreen
	default: // "not simulated", "reply (skipped)"
		return ansiGray
	}
}

// flowVerdictColor maps Hubble's own flow verdict (FORWARDED/DROPPED/AUDIT/...)
// to a color for the "flows" subcommand's output.
func flowVerdictColor(verdict string) string {
	switch verdict {
	case "FORWARDED":
		return ansiGreen
	case "DROPPED":
		return ansiRed
	case "AUDIT":
		return ansiYellow
	default:
		return ansiGray
	}
}

// colorizePadded formats s to width (left-justified, like %-<width>s) and
// then colors the padded result — the correct order so escape codes never
// throw off column alignment.
func colorizePadded(code, s string, width int) string {
	return colorize(code, fmt.Sprintf("%-*s", width, s))
}
