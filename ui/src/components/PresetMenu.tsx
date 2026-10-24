// Redesigned "Presets & Starters" entry point for the Policy Editor.
//
// The old version (a flat, wrapped row of buttons, one per generic
// template) stopped scaling the same way AddRuleMenu's flat preset list
// did before it grew a sticky header and a scroll clamp (see that
// component's own comment in RuleEditorCard.tsx) — hover-only descriptions
// and no grouping made it hard to tell templates apart at a glance once
// there were more than a handful, especially once CiliumClusterwideNetworkPolicy
// templates joined the namespaced ones with materially different blast
// radius. This groups by category (from templates.go's
// guardbeeCategoryAnnotation), always shows the description inline instead
// of only on hover, and badges a clusterwide template so its different
// scope is visible before it's loaded, not after.
//
// CNP/CCNP tabs: once there were enough CCNP starters to need their own
// "Cluster-wide (CCNP)" category, a user who only ever authors namespaced
// policies still had to scroll past them (and vice versa) in one combined
// list — splitting into two tabs, filtered on the same isClusterwide flag
// the CCNP badge already used, means either kind's starters are the first
// thing in view, not something to scroll past.

import { useMemo, useRef, useState } from 'react'
import { useAnchoredPosition } from '../shared/useAnchoredPosition'

export interface PresetMenuItem {
  id: string
  name: string
  description: string
  category: string
  isClusterwide: boolean
}

const FALLBACK_CATEGORY = 'General'

// The dropdown panel's own height cap, independent of how close to the
// bottom of the viewport the trigger sits — the previous viewport-relative-
// only calc(100vh - top - 16px) meant a panel opened from a trigger already
// fairly low on the page got almost no room at all, with no visual cue
// (no scrollbar track, no fade) that there was more to see below the fold.
const MAX_PANEL_HEIGHT = 420

function groupByCategory(presets: PresetMenuItem[]): [string, PresetMenuItem[]][] {
  const byCategory = new Map<string, PresetMenuItem[]>()
  for (const p of presets) {
    const key = p.category || FALLBACK_CATEGORY
    const list = byCategory.get(key) ?? []
    list.push(p)
    byCategory.set(key, list)
  }
  return Array.from(byCategory.entries())
}

export function PresetMenu({
  presets,
  onSelect,
}: {
  presets: PresetMenuItem[]
  onSelect: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'cnp' | 'ccnp'>('cnp')
  const triggerRef = useRef<HTMLButtonElement>(null)
  const pos = useAnchoredPosition(triggerRef, open)

  const cnpPresets = useMemo(() => presets.filter((p) => !p.isClusterwide), [presets])
  const ccnpPresets = useMemo(() => presets.filter((p) => p.isClusterwide), [presets])
  const groups = useMemo(
    () => groupByCategory(tab === 'cnp' ? cnpPresets : ccnpPresets),
    [tab, cnpPresets, ccnpPresets]
  )

  return (
    <div className="relative inline-block">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="border border-signal bg-signal/10 px-3 py-1.5 text-xs font-bold uppercase tracking-wider text-signal hover:bg-signal hover:text-void transition-colors cursor-pointer"
      >
        📦 Presets & Starters ▾
      </button>
      {open && pos && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div
            className="fixed z-30 flex w-96 flex-col border border-line-bright bg-panel-raised shadow-lg"
            style={{ top: pos.top, left: pos.left, maxHeight: `min(${MAX_PANEL_HEIGHT}px, calc(100vh - ${pos.top}px - 16px))` }}
          >
            <div className="flex shrink-0 border-b border-line">
              <button
                type="button"
                onClick={() => setTab('cnp')}
                className={`flex-1 px-3 py-1.5 text-[0.65rem] font-bold uppercase tracking-wider cursor-pointer ${
                  tab === 'cnp' ? 'bg-signal/10 text-signal' : 'text-ink-dim hover:text-ink'
                }`}
              >
                CiliumNetworkPolicy
              </button>
              <button
                type="button"
                onClick={() => setTab('ccnp')}
                className={`flex-1 border-l border-line px-3 py-1.5 text-[0.65rem] font-bold uppercase tracking-wider cursor-pointer ${
                  tab === 'ccnp' ? 'bg-signal/10 text-signal' : 'text-ink-dim hover:text-ink'
                }`}
              >
                Clusterwide (CCNP)
              </button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain">
              {groups.length === 0 && (
                <div className="px-3 py-3 text-xs text-ink-faint italic">
                  No {tab === 'cnp' ? 'namespaced' : 'clusterwide'} starters yet.
                </div>
              )}
              {groups.map(([category, items]) => (
                <div key={category}>
                  <div className="sticky top-0 z-10 border-b border-t border-line bg-panel-raised px-3 py-1.5 text-[0.6rem] font-bold uppercase tracking-wider text-ink-dim first:border-t-0">
                    {category}
                  </div>
                  {items.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        onSelect(item.id)
                        setOpen(false)
                      }}
                      className="block w-full border-b border-line px-3 py-2 text-left last:border-b-0 hover:bg-signal/10 cursor-pointer"
                    >
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                        {item.name}
                        {item.isClusterwide && (
                          <span className="border border-allow/50 bg-allow/10 px-1 text-[0.55rem] font-bold uppercase tracking-wider text-allow">
                            CCNP
                          </span>
                        )}
                      </div>
                      <div className="mt-0.5 text-[0.65rem] text-ink-dim leading-snug">{item.description}</div>
                    </button>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
