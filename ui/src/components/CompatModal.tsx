// Compatibility reference, as a modal opened from the header icon row (next
// to GitHub/homepage/theme) rather than a tab — this is reference info you
// check occasionally, not a primary workflow, so it doesn't need a
// permanent slot in the main navigation. Lists every version-gated
// construct GuardBee knows about (see ../../compat.go's featureGates), so
// "why was my candidate rejected" has somewhere to check instead of only
// the rejection error text. Read-only: mirrors compat.go's table verbatim,
// never edits it. Modal shell (focus trap, Escape, backdrop click) matches
// PolicyTextModal's own conventions.

import { useEffect, useRef, useState } from 'react'
import { fetchCompat, type CompatGate } from '../api'

const FOCUSABLE_SELECTOR = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

interface CompatModalProps {
  isOpen: boolean
  onClose: () => void
}

export function CompatModal({ isOpen, onClose }: CompatModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)

  const [pinned, setPinned] = useState<string | null>(null)
  const [gates, setGates] = useState<CompatGate[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!isOpen) return
    previousFocusRef.current = document.activeElement as HTMLElement | null
    closeButtonRef.current?.focus()
  }, [isOpen])

  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key === 'Tab' && panelRef.current) {
        const focusable = panelRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
      previousFocusRef.current?.focus()
    }
  }, [isOpen, onClose])

  // Fetched once per open, not on mount — this is a modal, not a
  // permanently-mounted tab, so there's no reason to hold a stale fetch
  // across opens if compat.go's table ever changes between them (e.g. a
  // hot-reloaded dev build).
  useEffect(() => {
    if (!isOpen) return
    setLoading(true)
    setError(null)
    fetchCompat()
      .then((res) => {
        setPinned(res.pinned)
        setGates(res.gates)
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false))
  }, [isOpen])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
      <div
        className="fixed inset-0 bg-void/80 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Compatibility"
        className="relative z-10 flex max-h-[85vh] w-full max-w-2xl flex-col border border-line-bright bg-panel shadow-2xl rise-in"
      >
        <div className="flex items-center justify-between border-b border-line bg-panel-raised px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 rounded-full bg-signal shadow-[0_0_8px_var(--color-signal-glow)]" />
            <h2 className="font-display text-sm font-bold tracking-[0.1em] text-ink uppercase">Compatibility</h2>
          </div>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            className="flex h-6 w-6 cursor-pointer items-center justify-center border border-line text-ink-dim transition-colors hover:border-signal hover:text-ink"
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-4">
          <p className="text-xs text-ink-dim leading-relaxed">
            GuardBee computes every verdict using Cilium{' '}
            <span className="font-semibold text-ink">{pinned ?? '…'}</span>'s policy engine semantics, regardless of
            what the cluster you're pointed at actually runs — see the version banner above when they drift. The
            constructs below are known to behave differently, or not exist at all, outside that pinned version:
            GuardBee refuses to parse a candidate using one rather than silently computing a verdict that
            misrepresents what it does.
          </p>

          {error && <div className="border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">{error}</div>}

          {loading && !error && <p className="text-xs text-ink-dim">Loading…</p>}

          {!loading && !error && gates.length === 0 && (
            <p className="text-xs text-ink-dim">No version-gated constructs known yet.</p>
          )}

          {!loading &&
            gates.map((g) => (
              <div key={g.name} className="border border-line bg-void/40 p-4 space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="font-mono text-xs text-ink">{g.name}</p>
                  <p className="font-display text-[0.6rem] uppercase tracking-wider text-ink-dim">
                    {g.minVersion && `Cilium ${g.minVersion}+`}
                    {g.minVersion && g.maxVersion && ' · '}
                    {g.maxVersion && `up to ${g.maxVersion}`}
                  </p>
                </div>
                <p className="text-xs text-ink-dim leading-relaxed">{g.reason}</p>
              </div>
            ))}
        </div>

        <div className="flex items-center justify-end border-t border-line bg-panel-raised px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="cursor-pointer bg-signal px-4 py-1.5 font-display text-xs font-bold tracking-wide text-void uppercase transition-opacity hover:opacity-90"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  )
}
