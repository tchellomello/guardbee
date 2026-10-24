// Full-size modal editor for a candidate policy's raw YAML, opened by
// clicking the compact sidebar textarea — comfortable hand-editing without
// fighting a 380px-wide, 15-row box.

import { useEffect, useRef } from 'react'

const FOCUSABLE_SELECTOR = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

interface PolicyTextModalProps {
  isOpen: boolean
  onClose: () => void
  value: string
  onChange?: (value: string) => void
  title?: string
  readOnly?: boolean
}

export function PolicyTextModal({
  isOpen,
  onClose,
  value,
  onChange,
  title = 'Edit Candidate Policy',
  readOnly = false,
}: PolicyTextModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)

  // Capture the pre-open focus target and move focus into the textarea in
  // the same effect (replacing the old `autoFocus` JSX attribute), so the
  // capture always runs before focus moves — no render-phase ref writes
  // needed to win a race against commit-time autoFocus.
  useEffect(() => {
    if (!isOpen) return
    previousFocusRef.current = document.activeElement as HTMLElement | null
    textareaRef.current?.focus()
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
        className="relative z-10 flex h-[85vh] w-full max-w-4xl flex-col border border-line-bright bg-panel shadow-2xl rise-in"
      >
        <div className="flex items-center justify-between border-b border-line bg-panel-raised px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 rounded-full bg-signal shadow-[0_0_8px_var(--color-signal-glow)]" />
            <h2 className="font-display text-sm font-bold tracking-[0.1em] text-ink uppercase">{title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="flex h-6 w-6 cursor-pointer items-center justify-center border border-line text-ink-dim transition-colors hover:border-signal hover:text-ink"
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        <textarea
          ref={textareaRef}
          value={value}
          onChange={readOnly ? undefined : (e) => onChange?.(e.target.value)}
          readOnly={readOnly}
          spellCheck={false}
          placeholder={'apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: ...\nspec:\n  ...'}
          className={`flex-1 resize-none border-none bg-void px-5 py-4 font-mono text-xs leading-relaxed text-ink placeholder:text-ink-faint focus:outline-none ${
            readOnly ? 'cursor-text' : ''
          }`}
        />

        <div className="flex items-center justify-between border-t border-line bg-panel-raised px-5 py-3">
          <span className="text-[0.65rem] text-ink-dim">
            {readOnly
              ? 'Esc or click outside to close — this is a read-only preview.'
              : 'Esc or click outside to close — changes apply immediately.'}
          </span>
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
