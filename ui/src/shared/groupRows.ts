import type { VerdictRow } from '../api'

// Collapses rows describing the same traffic pattern into one row whose
// count is the sum. Follow mode appends one row per judged flow, so a chatty
// pod would otherwise fill the table with identical lines; the one-shot API
// already dedups server-side (verdictRow.key in verdict.go) — same key here.
// "explanation" is deliberately not part of the key: it is derived from
// change, so it can't differ within a group. First-seen order is kept.
export function groupRows(rows: VerdictRow[]): VerdictRow[] {
  const byKey = new Map<string, VerdictRow>()
  for (const r of rows) {
    const k = [r.change, r.source, r.destination, r.protocol, r.port].join('\u0000')
    const hit = byKey.get(k)
    if (hit) hit.count += r.count
    else byKey.set(k, { ...r })
  }
  return [...byKey.values()]
}
