// How a connectivity test's notes and warnings read at a glance: an icon and
// a few words, with the server's full sentence one click away. Notes carry a
// stable code from the server (probes.go's note* constants), so the title is
// chosen by code, never by parsing the sentence; a code this UI doesn't know
// yet still shows, titled by its own first clause.

export interface ProbeNote {
  code: string
  text: string
}

const NOTE_TITLES: Record<string, { icon: string; title: string }> = {
  'udp-marker': { icon: '✉', title: 'One fixed 27-byte UDP marker, no reply wait' },
  'service-match': { icon: '⎈', title: 'Hostname matched a Kubernetes Service' },
  'hostname-best-effort': { icon: '≈', title: 'Hostname correlation is best-effort' },
  'ephemeral-entry': { icon: '⧉', title: 'Ephemeral entry stays until Pod replacement' },
  'runtime-bound': { icon: '⏱', title: 'Probe runtime bounded to 8 s' },
  'best-effort-correlation': { icon: '≈', title: 'Flow correlation is best-effort' },
  'nodes-off-path': { icon: '◌', title: 'Unavailable Hubble nodes, off this path' },
  'replace-mode': { icon: '⇄', title: 'Candidate replaces same-named live policies' },
  'additive-mode': { icon: '＋', title: 'Candidate added alongside live policies' },
  'policy-replaced': { icon: '⇄', title: 'A live policy is replaced in simulation' },
}

export function noteDisplay(note: ProbeNote): { icon: string; title: string } {
  return NOTE_TITLES[note.code] ?? { icon: 'ℹ', title: shortTitle(note.text) }
}

// Warnings are free-form server sentences ("Simulation inconclusive: …",
// "Hubble capture incomplete: …"); their lead-in before the first colon is
// already the short title. Without one, the first clause stands in.
export function warningDisplay(text: string): { title: string; detail: string } {
  const colon = text.indexOf(': ')
  if (colon > 0 && colon <= 48) return { title: text.slice(0, colon), detail: text.slice(colon + 2) }
  return { title: shortTitle(text), detail: text }
}

function shortTitle(text: string): string {
  const clause = text.split(/[.;:]\s/)[0]
  return clause.length <= 60 ? clause : `${clause.slice(0, 57).trimEnd()}…`
}
