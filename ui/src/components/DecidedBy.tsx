import { useState } from 'react'
import { fetchPolicyForEdit, type EditablePolicyModel, type Flow, type PolicyRef } from '../api'
import { attributionBadges, isEditablePolicyRef } from '../shared/attribution'

const DECISION_STYLES: Record<string, string> = {
  allowed: 'text-unchanged',
  denied: 'text-drop',
  'default-deny': 'text-drop',
  audit: 'text-allow',
}

// The flow's policy attribution, as `guardbee blame` prints it (blame.go's
// flowAttribution): which policy Cilium allowed or denied it by, each one a
// link into the Policy Editor when it can be opened there. Empty for flows
// that aren't a policy decision — nothing is guessed here.
export function DecidedBy({ flow, onEditPolicy }: { flow: Flow; onEditPolicy?: (model: EditablePolicyModel) => void }) {
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  if (!flow.decision) return null
  const badges = attributionBadges(flow)
  const style = DECISION_STYLES[flow.decision] ?? 'text-ink-dim'

  async function open(ref: PolicyRef) {
    if (!onEditPolicy) return
    setBusy(ref.display)
    setError(null)
    try {
      onEditPolicy(await fetchPolicyForEdit(ref.kind ?? '', ref.namespace ?? '', ref.name ?? ''))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(null)
    }
  }

  if (!badges) {
    return (
      <span data-decision={flow.decision} className={`font-mono text-[0.7rem] ${style}`}>
        {flow.decidedBy}
      </span>
    )
  }
  return (
    <div className="relative" data-decision={flow.decision}>
      <div className="flex flex-wrap items-center gap-1">
        <span className={`text-[0.65rem] ${style}`}>{badges.lead}</span>
        {badges.refs.map((ref) =>
          onEditPolicy && isEditablePolicyRef(ref) ? (
            <button
              key={ref.display}
              type="button"
              onClick={() => open(ref)}
              disabled={busy !== null}
              title={`Open the live ${ref.kind} in the Policy Editor`}
              className={`cursor-pointer border border-current/40 px-1.5 py-0.5 font-mono text-[0.65rem] hover:bg-panel-raised disabled:opacity-50 ${style}`}
            >
              {busy === ref.display ? '…' : `✎ ${ref.display}`}
            </button>
          ) : (
            <span key={ref.display} title={ref.labels?.join('\n')} className={`border border-line px-1.5 py-0.5 font-mono text-[0.65rem] ${style}`}>
              {ref.display}
            </span>
          )
        )}
      </div>
      {error && (
        <div role="alert" className="absolute left-0 top-full z-10 mt-1 w-64 border border-drop/40 bg-panel p-2 text-[0.65rem] text-drop shadow-lg">
          {error}
        </div>
      )}
    </div>
  )
}
