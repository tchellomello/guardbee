// "Save" control shared by the Verdict candidate box and the Policy
// Editor's output box: opens a small inline name field (prefilled with the
// entry this work was last saved as/loaded from, or the policy's own
// metadata.name), saves into the workspace, and confirms whether it created
// a new entry or updated an existing one.

import { useEffect, useRef, useState } from 'react'

export function SaveToWorkspace({
  defaultName,
  disabled,
  onSave,
}: {
  defaultName: string
  disabled?: boolean
  // Returns whether an existing same-named entry was updated.
  onSave: (name: string) => boolean
}) {
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState('')
  const [flash, setFlash] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (editing) inputRef.current?.select()
  }, [editing])

  useEffect(() => {
    if (!flash) return
    const t = setTimeout(() => setFlash(null), 2000)
    return () => clearTimeout(t)
  }, [flash])

  function commit() {
    const trimmed = name.trim()
    if (!trimmed) return
    setFlash(onSave(trimmed) ? '✓ Updated' : '✓ Saved')
    setEditing(false)
  }

  if (editing) {
    return (
      <span className="flex items-center gap-1">
        <input
          ref={inputRef}
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            // Inside the Verdict <form>, Enter would otherwise submit a run.
            if (e.key === 'Enter') {
              e.preventDefault()
              commit()
            } else if (e.key === 'Escape') {
              setEditing(false)
            }
          }}
          placeholder="Name"
          aria-label="Name to save this policy as"
          className="w-40 border border-line bg-void px-2 py-0.5 font-mono text-[0.7rem] text-ink focus:border-signal focus:outline-none"
        />
        <button
          type="button"
          onClick={commit}
          disabled={!name.trim()}
          className="border border-signal bg-signal/10 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal hover:text-void cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Save
        </button>
        <button
          type="button"
          onClick={() => setEditing(false)}
          aria-label="Cancel saving"
          className="px-1 text-xs text-ink-faint hover:text-ink cursor-pointer"
        >
          ✕
        </button>
      </span>
    )
  }

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => {
        setName(defaultName)
        setEditing(true)
      }}
      title="Save this policy to your workspace (header ▸ Saved policies) so you can come back to it"
      className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-signal cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
    >
      {flash ?? '💾 Save'}
    </button>
  )
}
