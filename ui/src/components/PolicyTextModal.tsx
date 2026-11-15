// Full-size modal editor for a candidate policy's raw YAML, opened by
// clicking the compact sidebar textarea — comfortable hand-editing without
// fighting a 380px-wide, 15-row box.

import { useEffect, useRef, type ReactNode } from 'react'

const FOCUSABLE_SELECTOR = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

interface PolicyTextModalProps {
  isOpen: boolean
  onClose: () => void
  value: string
  onChange?: (value: string) => void
  title?: string
  readOnly?: boolean
  // Surfaced above the textarea when a hand-edit/import failed to parse
  // against the real Cilium engine — same error-banner styling as the
  // sidebar's own validation banner (PolicyEditorPanel.tsx), just inside
  // the modal where the user is actually looking while typing.
  error?: string | null
  // A non-error heads-up (e.g. "valid, but the visual editor can't show
  // it") with an optional one-click action — amber, not the red error
  // styling, because the pasted text is fine.
  notice?: { message: string; actionLabel?: string; onAction?: () => void } | null
  // Extra footer controls left of Done (e.g. the Policy Editor's 💾 Save,
  // so a pasted policy can be saved without leaving the editor).
  footerActions?: ReactNode
  // Footer hint; defaults to the read-only or editable wording below.
  hint?: string
}

export function PolicyTextModal({
  isOpen,
  onClose,
  value,
  onChange,
  title = 'Edit Candidate Policy',
  readOnly = false,
  error = null,
  notice = null,
  footerActions = null,
  hint,
}: PolicyTextModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)

  // Callers pass onClose as an inline arrow, a new function on every render —
  // and every keystroke re-renders them (onChange → their state). Keeping it
  // in a ref lets the effects below depend on isOpen alone. When the keydown
  // effect depended on onClose, each keystroke ran its cleanup, which handed
  // focus back to the pre-open element: only the first typed character
  // reached the textarea, the rest went to the button behind the backdrop.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  // Capture the pre-open focus target and move focus into the textarea in
  // the same effect (replacing the old `autoFocus` JSX attribute), so the
  // capture always runs before focus moves — no render-phase ref writes
  // needed to win a race against commit-time autoFocus. Focus is handed
  // back only when the modal actually closes (this effect's cleanup).
  useEffect(() => {
    if (!isOpen) return
    previousFocusRef.current = document.activeElement as HTMLElement | null
    textareaRef.current?.focus()
    return () => previousFocusRef.current?.focus()
  }, [isOpen])

  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCloseRef.current()
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
    return () => window.removeEventListener('keydown', handleKeyDown)
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

        {error && (
          <div className="border-b border-drop/40 bg-drop/10 px-5 py-2 text-xs text-drop">
            <span className="font-mono break-words">{error}</span>
          </div>
        )}

        {notice && (
          <div className="flex items-center justify-between gap-3 border-b border-allow/40 bg-allow/10 px-5 py-2 text-xs text-allow">
            <span className="break-words">{notice.message}</span>
            {notice.actionLabel && notice.onAction && (
              <button
                type="button"
                onClick={notice.onAction}
                className="shrink-0 cursor-pointer border border-allow/60 px-2.5 py-1 font-display text-[0.65rem] font-bold tracking-wide uppercase hover:bg-allow/20"
              >
                {notice.actionLabel}
              </button>
            )}
          </div>
        )}

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
            {hint ??
              (readOnly
                ? 'Esc or click outside to close — this is a read-only preview.'
                : 'Esc or click outside to close — your text is kept as you type it.')}
          </span>
          <div className="flex items-center gap-3">
            {footerActions}
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
    </div>
  )
}
