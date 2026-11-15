// A text input with an autocomplete list of values seen in real traffic
// (pods, labels, ports, drop reasons… see shared/flowFilter.ts's
// suggestion builders). Replaces a native <datalist>, which renders
// differently in every browser, can't rank or highlight matches, and in a
// comma-separated field can only complete the whole value.
//
// Keyboard: ↓/↑ move, Enter or Tab picks, Esc closes. Enter only picks while
// the list is open, so it can't accidentally submit the surrounding form.

import { useId, useMemo, useRef, useState } from 'react'
import { completeToken, matchSuggestions } from '../shared/flowFilter'

export function SuggestInput({
  value,
  onChange,
  suggestions,
  multi,
  placeholder,
  className,
}: {
  value: string
  onChange: (value: string) => void
  // Candidate values, most relevant first.
  suggestions: string[]
  // A comma-separated list field: complete the token after the last comma.
  multi: boolean
  placeholder?: string
  className?: string
}) {
  const listId = useId()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const matches = useMemo(() => matchSuggestions(value, suggestions, multi), [value, suggestions, multi])
  const showing = open && matches.length > 0
  const token = (multi ? value.slice(value.lastIndexOf(',') + 1) : value).trim()

  function pick(v: string) {
    onChange(completeToken(value, v, multi))
    setOpen(false)
    inputRef.current?.focus()
  }

  return (
    <div className="relative">
      <input
        ref={inputRef}
        value={value}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        role="combobox"
        aria-autocomplete="list"
        aria-expanded={showing}
        aria-controls={listId}
        aria-activedescendant={showing ? `${listId}-${active}` : undefined}
        onChange={(e) => {
          onChange(e.target.value)
          setOpen(true)
          setActive(0)
        }}
        onFocus={() => {
          setOpen(true)
          setActive(0)
        }}
        onBlur={() => setOpen(false)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            if (!matches.length) return
            e.preventDefault()
            setOpen(true)
            const step = e.key === 'ArrowDown' ? 1 : -1
            setActive((i) => (i + step + matches.length) % matches.length)
          } else if ((e.key === 'Enter' || e.key === 'Tab') && showing && token !== matches[active]) {
            e.preventDefault()
            pick(matches[active])
          } else if (e.key === 'Escape' && showing) {
            e.preventDefault()
            setOpen(false)
          }
        }}
        className={className}
      />
      {showing && (
        <ul
          id={listId}
          role="listbox"
          className="absolute left-0 right-0 top-full z-30 mt-1 max-h-60 overflow-y-auto border border-line-bright bg-panel py-1 shadow-xl"
        >
          {matches.map((m, i) => (
            <li
              key={m}
              id={`${listId}-${i}`}
              role="option"
              aria-selected={i === active}
              // mousedown, not click: picking must happen before the
              // input's blur closes the list.
              onMouseDown={(e) => {
                e.preventDefault()
                pick(m)
              }}
              onMouseEnter={() => setActive(i)}
              className={`cursor-pointer truncate px-2.5 py-1.5 font-mono text-xs ${
                i === active ? 'bg-signal/15 text-ink' : 'text-ink-dim'
              }`}
              title={m}
            >
              <Highlight text={m} token={token} />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// Bolds the first occurrence of what's been typed, so it's clear why a
// value matched (a substring match isn't obvious from the value alone).
function Highlight({ text, token }: { text: string; token: string }) {
  const i = token ? text.toLowerCase().indexOf(token.toLowerCase()) : -1
  if (i < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, i)}
      <span className="font-bold text-signal">{text.slice(i, i + token.length)}</span>
      {text.slice(i + token.length)}
    </>
  )
}
