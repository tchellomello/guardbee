import type { VerdictChange } from '../api'

// The chip palette every tab shares, so a verdict or change reads the same
// wherever it appears (Verdict, Flows, connectivity tests).

// Visual language matches the CLI's own colorize/changeColor (colors.go):
// red for NEWLY_DROPPED, amber for NEWLY_ALLOWED, green for UNCHANGED —
// same categories, same meaning, just rendered as chips instead of ANSI.
export const CHANGE_STYLES: Record<VerdictChange, string> = {
  NEWLY_DROPPED: 'border-drop/40 bg-drop/10 text-drop',
  NEWLY_ALLOWED: 'border-allow/40 bg-allow/10 text-allow',
  UNCHANGED: 'border-unchanged/40 bg-unchanged/10 text-unchanged',
}

// Filled variants, reserved for the newly-dropped/newly-allowed summary
// chips only — those are the actual answer this tool exists to give, so
// they get the same solid-fill treatment as the primary "Run verdict"
// button instead of the muted border+low-opacity look every other chip uses.
export const HEADLINE_CHIP_STYLES: Record<'NEWLY_DROPPED' | 'NEWLY_ALLOWED', string> = {
  NEWLY_DROPPED: 'border-drop bg-drop text-void font-bold',
  NEWLY_ALLOWED: 'border-allow bg-allow text-void font-bold',
}

// Matches the CLI's own flowVerdictColor (colors.go): green for FORWARDED,
// red for DROPPED, amber for AUDIT.
export const VERDICT_STYLES: Record<string, string> = {
  FORWARDED: 'border-unchanged/40 bg-unchanged/10 text-unchanged',
  DROPPED: 'border-drop/40 bg-drop/10 text-drop',
  AUDIT: 'border-allow/40 bg-allow/10 text-allow',
}
