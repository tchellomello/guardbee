// Shared namespace / --all-namespaces control, mirroring the CLI's own
// -n/--namespace and -A/--all-namespaces flags (see kube.go's
// resolveNamespace) so the same mental model carries over from the CLI.
// Offers real namespace names from the cluster as autocomplete suggestions
// (GET /api/namespaces) via a native <datalist> — the input still accepts
// free text, so a namespace that doesn't exist yet (or isn't visible to
// this list call for some reason) is never blocked, just not suggested.

import { useEffect, useState } from 'react'
import { fetchNamespaces } from '../api'

interface NamespaceScopeProps {
  namespace: string
  onNamespaceChange: (value: string) => void
  allNamespaces: boolean
  onAllNamespacesChange: (value: boolean) => void
}

export function NamespaceScope({
  namespace,
  onNamespaceChange,
  allNamespaces,
  onAllNamespacesChange,
}: NamespaceScopeProps) {
  const [options, setOptions] = useState<string[]>([])

  useEffect(() => {
    let cancelled = false
    fetchNamespaces()
      .then((res) => {
        if (!cancelled) setOptions(res.namespaces)
      })
      .catch(() => {
        // Autocomplete is a convenience, not a requirement — if the list
        // call fails for any reason, the namespace field still works as a
        // plain text input, just without suggestions.
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="space-y-3">
      <Field label="Namespace">
        <input
          type="text"
          list="namespace-options"
          value={namespace}
          onChange={(e) => onNamespaceChange(e.target.value)}
          disabled={allNamespaces}
          placeholder="myapp"
          className="w-full border border-line bg-void px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none disabled:cursor-not-allowed disabled:text-ink-faint"
        />
        <datalist id="namespace-options">
          {options.map((ns) => (
            <option key={ns} value={ns} />
          ))}
        </datalist>
      </Field>
      <CheckRow label="All namespaces" checked={allNamespaces} onChange={onAllNamespacesChange} />
    </div>
  )
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[0.65rem] font-semibold tracking-[0.12em] text-ink-dim uppercase">
        {label}
      </span>
      {children}
    </label>
  )
}

export function CheckRow({
  label,
  checked,
  onChange,
}: {
  label: string
  checked: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2.5 text-sm text-ink-dim select-none hover:text-ink">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="peer sr-only"
      />
      {/* peer-focus-visible (not :focus) so the ring only shows for keyboard
          navigation, matching every other focusable control in this app
          (e.g. PolicyEditorPanel's text inputs use focus:border-signal the
          same way) — requires the input to precede this span in the DOM for
          Tailwind's peer-* sibling selector to apply, hence the reorder. */}
      <span
        className={`flex h-4 w-4 shrink-0 items-center justify-center border transition-colors peer-focus-visible:ring-2 peer-focus-visible:ring-signal peer-focus-visible:ring-offset-1 peer-focus-visible:ring-offset-void ${
          checked ? 'border-signal bg-signal/20' : 'border-line'
        }`}
      >
        {checked && <span className="h-1.5 w-1.5 bg-signal" />}
      </span>
      {label}
    </label>
  )
}
