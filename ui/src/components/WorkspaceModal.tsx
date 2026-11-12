// The policy workspace: every policy saved from the Verdict tab or the
// Policy Editor, reopenable in either, downloadable as .yaml. Modal shell
// (focus trap, Escape, backdrop click) matches CompatModal/PolicyTextModal.

import { useEffect, useRef, useState } from 'react'
import { downloadTextFile } from '../shared/tableExport'
import { countDocuments, type SavedPolicy } from '../shared/workspace'

const FOCUSABLE_SELECTOR = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'

interface WorkspaceModalProps {
  isOpen: boolean
  onClose: () => void
  policies: SavedPolicy[]
  onOpenInVerdict: (p: SavedPolicy) => void
  onOpenInEditor: (p: SavedPolicy) => void
  onRename: (id: string, name: string) => void
  onDuplicate: (id: string) => void
  onDelete: (id: string) => void
}

export function WorkspaceModal({
  isOpen,
  onClose,
  policies,
  onOpenInVerdict,
  onOpenInEditor,
  onRename,
  onDuplicate,
  onDelete,
}: WorkspaceModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const [renamingId, setRenamingId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState('')
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    if (!isOpen) return
    previousFocusRef.current = document.activeElement as HTMLElement | null
    closeButtonRef.current?.focus()
    setRenamingId(null)
    setConfirmDeleteId(null)
  }, [isOpen])

  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // Escape first backs out of an inline rename/delete confirmation.
        if (renamingId || confirmDeleteId) {
          setRenamingId(null)
          setConfirmDeleteId(null)
          return
        }
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
    }
  }, [isOpen, onClose, renamingId, confirmDeleteId])

  useEffect(() => {
    if (isOpen) return
    previousFocusRef.current?.focus()
  }, [isOpen])

  if (!isOpen) return null

  const q = filter.trim().toLowerCase()
  const shown = q
    ? policies.filter((p) => p.name.toLowerCase().includes(q) || p.namespace.toLowerCase().includes(q))
    : policies

  function commitRename(id: string) {
    onRename(id, renameValue)
    setRenamingId(null)
  }

  const actionClass =
    'font-display text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-signal transition-colors cursor-pointer'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
      <div className="fixed inset-0 bg-void/80 backdrop-blur-xs transition-opacity" onClick={onClose} aria-hidden="true" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Saved policies"
        className="relative z-10 flex max-h-[85vh] w-full max-w-3xl flex-col border border-line-bright bg-panel shadow-2xl rise-in"
      >
        <div className="flex items-center justify-between border-b border-line bg-panel-raised px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <span className="h-2 w-2 rounded-full bg-signal shadow-[0_0_8px_var(--color-signal-glow)]" />
            <h2 className="font-display text-sm font-bold tracking-[0.1em] text-ink uppercase">Saved policies</h2>
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

        <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
          <p className="text-xs text-ink-dim leading-relaxed">
            Policies you've saved with <span className="font-semibold text-ink">💾 Save</span> in the Verdict tab or
            the Policy Editor. They're stored in this browser only: never sent to the cluster, and not shared
            with other browsers. Download one as .yaml to keep it anywhere else.
          </p>

          {policies.length > 3 && (
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name or namespace"
              aria-label="Filter saved policies"
              className="w-full border border-line bg-void px-3 py-1.5 text-xs text-ink focus:border-signal focus:outline-none"
            />
          )}

          {policies.length === 0 && (
            <p className="border border-dashed border-line px-4 py-6 text-center text-xs text-ink-faint">
              Nothing saved yet. Use 💾 Save next to the candidate YAML in the Verdict tab, or next to Copy YAML in
              the Policy Editor.
            </p>
          )}

          {shown.map((p) => {
            const docs = countDocuments(p.candidateYAML)
            return (
              <div key={p.id} className="border border-line bg-void/40 p-3 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  {renamingId === p.id ? (
                    <input
                      autoFocus
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') commitRename(p.id)
                      }}
                      onBlur={() => commitRename(p.id)}
                      aria-label="New name"
                      className="flex-1 border border-signal bg-void px-2 py-0.5 font-mono text-xs text-ink focus:outline-none"
                    />
                  ) : (
                    <p className="font-mono text-xs font-semibold text-ink break-all">{p.name}</p>
                  )}
                  <div className="flex flex-wrap items-center gap-1.5 text-[0.6rem] uppercase tracking-wider">
                    <span className="border border-line px-1.5 py-0.5 text-ink-dim">
                      {p.origin === 'editor' ? 'Editor draft' : 'Verdict candidate'}
                    </span>
                    <span className="border border-line px-1.5 py-0.5 font-mono normal-case text-ink-dim">
                      {p.allNamespaces || !p.namespace ? 'all namespaces' : p.namespace}
                    </span>
                    {docs > 1 && (
                      <span
                        className="border border-signal/40 bg-signal/5 px-1.5 py-0.5 text-signal"
                        title="Candidate plus extra policies, e.g. Allow/Deny exceptions"
                      >
                        {docs} policies
                      </span>
                    )}
                    <span className="text-ink-faint normal-case">{new Date(p.savedAt).toLocaleString()}</span>
                  </div>
                </div>

                {confirmDeleteId === p.id ? (
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-drop">Delete "{p.name}"? This can't be undone.</span>
                    <button
                      type="button"
                      onClick={() => {
                        onDelete(p.id)
                        setConfirmDeleteId(null)
                      }}
                      className="border border-drop bg-drop px-2 py-0.5 text-[0.65rem] font-bold uppercase text-void cursor-pointer"
                    >
                      Delete
                    </button>
                    <button type="button" onClick={() => setConfirmDeleteId(null)} className={actionClass}>
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex flex-wrap items-center gap-3">
                    <button
                      type="button"
                      onClick={() => onOpenInVerdict(p)}
                      className="border border-signal bg-signal/10 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal hover:text-void cursor-pointer"
                    >
                      Open in Verdict
                    </button>
                    {p.editorModel && (
                      <button
                        type="button"
                        onClick={() => onOpenInEditor(p)}
                        className="border border-signal/40 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal/10 cursor-pointer"
                      >
                        Open in Editor
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() =>
                        downloadTextFile(`${p.name.replace(/[^A-Za-z0-9._-]+/g, '-')}.yaml`, p.candidateYAML, 'application/yaml')
                      }
                      className={actionClass}
                    >
                      Download .yaml
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setRenamingId(p.id)
                        setRenameValue(p.name)
                      }}
                      className={actionClass}
                    >
                      Rename
                    </button>
                    <button type="button" onClick={() => onDuplicate(p.id)} className={actionClass}>
                      Duplicate
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmDeleteId(p.id)}
                      className="font-display text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-drop transition-colors cursor-pointer"
                    >
                      Delete
                    </button>
                  </div>
                )}
              </div>
            )
          })}
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
