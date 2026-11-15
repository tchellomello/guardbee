// Helpers for inputs that edit structured policy data as free text. The
// pattern every one of them must follow: the input shows the user's own
// draft text, and the model is derived from that draft — never the other
// way round. Re-deriving the input's text from the parsed model on every
// keystroke drops anything not yet valid (a trailing ", ", a half-typed or
// momentarily duplicate label key, a value typed before its key).

// "10.0.0.0/8, 192.168.1.0/24" → ["10.0.0.0/8", "192.168.1.0/24"]. Empty
// pieces (a trailing comma mid-typing) are simply not entries yet.
export function parseCommaList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
}

export function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
}

// One editable key=value row. `id` keeps React's row identity stable while
// the key itself is being typed (keying rows by label name or index is what
// made rows merge, reorder and swap focus).
export interface LabelRow {
  id: number
  key: string
  value: string
}

export function labelsToRows(labels: Record<string, string>, firstId: number): LabelRow[] {
  return Object.entries(labels).map(([key, value], i) => ({ id: firstId + i, key, value }))
}

// Rows → matchLabels. A row with an empty key isn't a label yet; a repeated
// key is ignored after its first row (duplicateLabelKeys flags it to the user)
// rather than letting the later row silently overwrite the earlier value.
export function rowsToLabels(rows: LabelRow[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const row of rows) {
    const key = row.key.trim()
    if (!key || key in out) continue
    out[key] = row.value
  }
  return out
}

export function duplicateLabelKeys(rows: LabelRow[]): Set<string> {
  const seen = new Set<string>()
  const dup = new Set<string>()
  for (const row of rows) {
    const key = row.key.trim()
    if (!key) continue
    if (seen.has(key)) dup.add(key)
    seen.add(key)
  }
  return dup
}

export function sameLabels(a: Record<string, string>, b: Record<string, string>): boolean {
  const ak = Object.keys(a)
  return ak.length === Object.keys(b).length && ak.every((k) => k in b && a[k] === b[k])
}
