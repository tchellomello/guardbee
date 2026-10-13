import { useEffect } from 'react'

interface VerdictHelpModalProps {
  isOpen: boolean
  onClose: () => void
  initialCategory?: string | null
}

export function VerdictHelpModal({ isOpen, onClose, initialCategory }: VerdictHelpModalProps) {
  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-void/80 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Dialog */}
      <div className="relative w-full max-w-2xl max-h-[90vh] flex flex-col border border-line-bright bg-panel shadow-2xl text-ink font-mono text-xs overflow-hidden rise-in z-10">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-line px-5 py-3.5 bg-panel-raised">
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 rounded-full bg-signal shadow-[0_0_8px_var(--color-signal-glow)]" />
            <h2 className="font-display text-sm font-bold tracking-[0.1em] uppercase text-ink">
              Verdict Semantics & Flow Guide
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-6 w-6 items-center justify-center border border-line text-ink-dim hover:border-signal hover:text-ink transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          <p className="text-xs text-ink-dim leading-relaxed">
            Every sampled Hubble flow is judged twice using Cilium's native <code className="text-signal">pkg/policy</code> engine: once against today's live cluster policies (baseline), and once with your candidate policy added.
          </p>

          <div className="space-y-4">
            {/* Newly Dropped */}
            <div
              className={`p-3.5 border transition-all ${
                initialCategory === 'newly dropped'
                  ? 'border-drop bg-drop/10 ring-1 ring-drop'
                  : 'border-drop/40 bg-drop/5'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider border border-drop/40 bg-drop/10 text-drop">
                  NEWLY DROPPED
                </span>
                <span className="text-[0.7rem] text-drop font-semibold tracking-wide uppercase">
                  Regression / Breaking Change
                </span>
              </div>
              <p className="text-ink text-xs leading-relaxed">
                Traffic that is allowed under today's cluster policies, but would be <strong className="text-drop">DENIED</strong> if this candidate merges.
              </p>
              <p className="mt-1 text-ink-dim text-[0.7rem] leading-relaxed">
                Common causes: introducing a policy selecting a workload switches it to default-deny, breaking unmentioned ports like Prometheus metrics scraping or kubelet health probes.
              </p>
            </div>

            {/* Newly Allowed */}
            <div
              className={`p-3.5 border transition-all ${
                initialCategory === 'newly allowed'
                  ? 'border-allow bg-allow/10 ring-1 ring-allow'
                  : 'border-allow/40 bg-allow/5'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider border border-allow/40 bg-allow/10 text-allow">
                  NEWLY ALLOWED
                </span>
                <span className="text-[0.7rem] text-allow font-semibold tracking-wide uppercase">
                  Exposure Change
                </span>
              </div>
              <p className="text-ink text-xs leading-relaxed">
                Traffic that was previously blocked or not explicitly allowed, but would now be <strong className="text-allow">ALLOWED</strong> by the candidate.
              </p>
              <p className="mt-1 text-ink-dim text-[0.7rem] leading-relaxed">
                Review these flows to confirm that newly opened ports or peer relationships are intentional.
              </p>
            </div>

            {/* Unchanged */}
            <div
              className={`p-3.5 border transition-all ${
                initialCategory === 'unchanged'
                  ? 'border-unchanged bg-unchanged/10 ring-1 ring-unchanged'
                  : 'border-unchanged/40 bg-unchanged/5'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider border border-unchanged/40 bg-unchanged/10 text-unchanged">
                  UNCHANGED
                </span>
                <span className="text-[0.7rem] text-unchanged font-semibold tracking-wide uppercase">
                  Identical Verdict
                </span>
              </div>
              <p className="text-ink text-xs leading-relaxed">
                Traffic whose verdict is identical before and after applying the candidate (allowed → allowed, or denied → denied).
              </p>
              <p className="mt-1 text-ink-dim text-[0.7rem] leading-relaxed">
                Confirms existing application traffic continues working as intended. Check <code className="text-signal">Show unchanged</code> to see individual flow rows in the results table.
              </p>
            </div>

            {/* Not Simulated */}
            <div
              className={`p-3.5 border transition-all ${
                initialCategory === 'not simulated'
                  ? 'border-signal bg-signal/10 ring-1 ring-signal'
                  : 'border-line-bright bg-panel-raised/50'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider border border-line-bright bg-panel-raised text-ink-dim">
                  NOT SIMULATED
                </span>
                <span className="text-[0.7rem] text-ink-dim font-semibold tracking-wide uppercase">
                  Layer 7 & FQDN Rules
                </span>
              </div>
              <p className="text-ink text-xs leading-relaxed">
                Flows filtered by HTTP path/method (L7) or DNS names (toFQDNs).
              </p>
              <p className="mt-1 text-ink-dim text-[0.7rem] leading-relaxed">
                These verdicts are decided in Cilium's Envoy proxy or local DNS proxy, not the L3/L4 BPF datapath policy engine. The simulator explicitly flags them rather than guessing.
              </p>
            </div>

            {/* Reply Skipped */}
            <div
              className={`p-3.5 border transition-all ${
                initialCategory === 'reply skipped'
                  ? 'border-signal bg-signal/10 ring-1 ring-signal'
                  : 'border-line-bright bg-panel-raised/50'
              }`}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider border border-line-bright bg-panel-raised text-ink-dim">
                  REPLY SKIPPED
                </span>
                <span className="text-[0.7rem] text-ink-dim font-semibold tracking-wide uppercase">
                  Established Return Packets
                </span>
              </div>
              <p className="text-ink text-xs leading-relaxed">
                Return packets belonging to an already-established connection (conntrack <code className="text-signal">is_reply</code>).
              </p>
              <p className="mt-1 text-ink-dim text-[0.7rem] leading-relaxed">
                Connection tracking automatically allows reply packets. CiliumNetworkPolicy ingress rules only gate initial connection establishment.
              </p>
            </div>
          </div>

          {/* Caveats / Technical Notes */}
          <div className="border-t border-line pt-4 space-y-3 text-[0.7rem] text-ink-dim">
            <h3 className="font-display text-xs font-bold uppercase tracking-wider text-signal">
              Important Datapath Caveats
            </h3>
            <p>
              <strong className="text-ink">Hubble Buffer Ring:</strong> Hubble Relay aggregates flows into a rolling, fixed-size ring buffer for the entire cluster. When querying low-traffic namespaces, fewer matching flows may be present than requested. Use <strong className="text-ink">Follow (live)</strong> to sample continuously over time.
            </p>
            <p>
              <strong className="text-ink">Non-pod Peers:</strong> Endpoints shown as <code className="text-signal">reserved:host</code> are cluster nodes (frequently kubelet TCP health probes on port 8080/8123/etc.). <code className="text-signal">reserved:world</code> represents traffic outside the cluster.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end border-t border-line px-5 py-3 bg-panel-raised">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 bg-signal text-void font-display text-xs font-bold uppercase tracking-wide hover:opacity-90 transition-opacity cursor-pointer"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  )
}
