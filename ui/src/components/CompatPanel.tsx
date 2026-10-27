// Compatibility reference — lists every version-gated construct GuardBee
// knows about (see ../../compat.go's featureGates), so "why was my
// candidate rejected" has a page to check instead of only the rejection
// error text from Policy Editor validation/import. Read-only: this mirrors
// compat.go's table verbatim, it never edits it.

import { useEffect, useState } from 'react'
import { fetchCompat, type CompatGate } from '../api'

export function CompatPanel() {
  const [pinned, setPinned] = useState<string | null>(null)
  const [gates, setGates] = useState<CompatGate[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchCompat()
      .then((res) => {
        setPinned(res.pinned)
        setGates(res.gates)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6">
      <div className="rise-in border border-line bg-panel p-5 space-y-2">
        <p className="font-display text-xs uppercase tracking-wider text-ink">Engine version</p>
        <p className="text-xs text-ink-dim">
          GuardBee computes every verdict using Cilium{' '}
          <span className="font-semibold text-ink">{pinned ?? '…'}</span>'s policy engine semantics, regardless of
          what the cluster you're pointed at actually runs — see the version banner above when they drift. The
          constructs below are the ones known to behave differently, or to not exist at all, outside that pinned
          version: GuardBee refuses to parse a candidate using one rather than silently computing a verdict that
          misrepresents what it does.
        </p>
      </div>

      {error && (
        <div className="rise-in border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">{error}</div>
      )}

      {loading && !error && <p className="text-xs text-ink-dim">Loading…</p>}

      {!loading && !error && gates.length === 0 && (
        <div className="border border-line bg-panel p-8 text-center text-ink-dim">
          <p className="text-xs">No version-gated constructs known yet.</p>
        </div>
      )}

      {!loading && gates.length > 0 && (
        <div className="space-y-4 rise-in">
          {gates.map((g) => (
            <div key={g.name} className="border border-line bg-panel p-5 space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-sm text-ink">{g.name}</p>
                <p className="font-display text-[0.65rem] uppercase tracking-wider text-ink-dim">
                  {g.minVersion && `Cilium ${g.minVersion}+`}
                  {g.minVersion && g.maxVersion && ' · '}
                  {g.maxVersion && `up to ${g.maxVersion}`}
                </p>
              </div>
              <p className="text-xs text-ink-dim leading-relaxed">{g.reason}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
