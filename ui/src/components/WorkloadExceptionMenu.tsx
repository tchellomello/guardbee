// Per-row "Allow / Deny" control on a NEWLY_DROPPED/NEWLY_ALLOWED verdict
// row: shows the affected workload's real identity labels (straight off the
// Hubble flow, i.e. what Cilium's selectors actually match), lets the user
// pick which ones scope the exception, and appends a separate per-workload
// exception policy to the candidate — see shared/workloadException.ts.

import { useMemo, useRef, useState } from 'react'
import type { VerdictRow } from '../api'
import { useAnchoredPosition } from '../shared/useAnchoredPosition'
import {
  buildExceptionPolicyYAML,
  defaultSelectedLabels,
  exceptionTargets,
} from '../shared/workloadException'

export function WorkloadExceptionMenu({
  row,
  onAddException,
}: {
  row: VerdictRow
  onAddException: (policyYAML: string) => void
}) {
  const targets = useMemo(() => exceptionTargets(row), [row])
  const [open, setOpen] = useState(false)
  const [targetIdx, setTargetIdx] = useState(0)
  const [selected, setSelected] = useState<Record<string, string>>({})
  const [showYAML, setShowYAML] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const pos = useAnchoredPosition(triggerRef, open)

  if (targets.length === 0) return null
  const target = targets[Math.min(targetIdx, targets.length - 1)]
  // The action that undoes this row's change is the obvious default:
  // allow what would newly break, deny what would newly open up.
  const suggested: 'allow' | 'deny' = row.change === 'NEWLY_DROPPED' ? 'allow' : 'deny'
  const hasSelector = Object.keys(selected).length > 0

  function selectTarget(i: number) {
    setTargetIdx(i)
    setSelected(defaultSelectedLabels(targets[i]))
  }

  function toggleLabel(key: string, value: string) {
    setSelected((prev) => {
      const next = { ...prev }
      if (key in next) delete next[key]
      else next[key] = value
      return next
    })
  }

  function apply(action: 'allow' | 'deny') {
    onAddException(buildExceptionPolicyYAML(target, selected, action, row.protocol, row.port))
    setOpen(false)
  }

  const peerLabel =
    target.peer.kind === 'entity'
      ? `entity ${target.peer.entity}`
      : target.peer.kind === 'pod'
      ? `${target.peer.namespace} pods with ${target.peer.label[0]}=${target.peer.label[1]}`
      : target.peer.cidr

  return (
    <div className="relative inline-block">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => {
          if (!open) selectTarget(targetIdx)
          setOpen((v) => !v)
        }}
        title="Show this workload's detected labels and add an allow/deny exception for just this workload"
        className="whitespace-nowrap border border-signal/40 bg-signal/5 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal/10 cursor-pointer"
      >
        Allow / Deny ▾
      </button>
      {open && pos && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div
            className="fixed z-30 w-96 space-y-3 overflow-y-auto overscroll-contain border border-line-bright bg-panel-raised p-3 text-xs shadow-lg"
            style={{ top: pos.top, right: pos.right, maxHeight: `calc(100vh - ${pos.top}px - 16px)` }}
          >
            {targets.length > 1 && (
              <div className="space-y-1.5">
                <p className="text-[0.65rem] text-ink-dim">
                  Both sides changed: the source's egress and the destination's ingress. The flow needs an
                  exception on each side.
                </p>
                <div className="flex border border-line">
                  {targets.map((t, i) => (
                    <button
                      key={t.direction}
                      type="button"
                      onClick={() => selectTarget(i)}
                      className={`flex-1 px-2 py-1 text-[0.65rem] font-bold uppercase tracking-wider cursor-pointer ${
                        i === targetIdx ? 'bg-signal/10 text-signal' : 'text-ink-dim hover:text-ink'
                      }`}
                    >
                      {t.direction}
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div>
              <div className="text-[0.6rem] font-bold uppercase tracking-wider text-ink-dim">
                Workload ({target.direction} side)
              </div>
              <div className="mt-0.5 font-mono text-ink break-all">
                {target.subjectNamespace}/{target.subjectPod}
              </div>
            </div>

            <div>
              <div className="text-[0.6rem] font-bold uppercase tracking-wider text-ink-dim">
                Detected labels: pick the ones that select this workload
              </div>
              <div className="mt-1 space-y-1">
                {target.subjectLabels.map(([k, v]) => (
                  <label key={k} className="flex cursor-pointer items-start gap-2 font-mono text-[0.7rem] text-ink">
                    <input
                      type="checkbox"
                      checked={selected[k] === v}
                      onChange={() => toggleLabel(k, v)}
                      className="mt-0.5 accent-signal"
                    />
                    <span className="break-all">
                      {k}=<span className="text-signal">{v}</span>
                    </span>
                  </label>
                ))}
              </div>
              {!hasSelector && (
                <p className="mt-1 text-[0.65rem] text-drop">Pick at least one label, or the exception would select every pod in {target.subjectNamespace}.</p>
              )}
            </div>

            <div>
              <div className="text-[0.6rem] font-bold uppercase tracking-wider text-ink-dim">
                {target.direction === 'egress' ? 'To' : 'From'}
              </div>
              <div className="mt-0.5 font-mono text-ink">
                {peerLabel} · {row.protocol}:{row.port}
              </div>
            </div>

            <p className="text-[0.65rem] leading-snug text-ink-dim">
              Adds a separate policy to the candidate (as another YAML document) and re-runs the verdict. Your
              original policy isn't modified.
            </p>

            <div className="flex items-center gap-2">
              {(['allow', 'deny'] as const).map((action) => (
                <button
                  key={action}
                  type="button"
                  disabled={!hasSelector}
                  onClick={() => apply(action)}
                  className={`flex-1 border px-3 py-1.5 font-bold uppercase tracking-wider cursor-pointer disabled:cursor-not-allowed disabled:opacity-40 ${
                    action === 'allow'
                      ? action === suggested
                        ? 'border-unchanged bg-unchanged text-void'
                        : 'border-unchanged/40 text-unchanged hover:bg-unchanged/10'
                      : action === suggested
                      ? 'border-drop bg-drop text-void'
                      : 'border-drop/40 text-drop hover:bg-drop/10'
                  }`}
                >
                  {action}
                </button>
              ))}
              <button
                type="button"
                onClick={() => setShowYAML((v) => !v)}
                className="text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-signal cursor-pointer"
              >
                {showYAML ? 'Hide YAML' : 'YAML'}
              </button>
            </div>

            {showYAML && hasSelector && (
              <pre className="max-h-64 overflow-auto border border-line bg-void p-2 font-mono text-[0.65rem] leading-relaxed text-ink">
                {buildExceptionPolicyYAML(target, selected, suggested, row.protocol, row.port)}
              </pre>
            )}
          </div>
        </>
      )}
    </div>
  )
}
