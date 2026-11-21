// Small presentational pieces shared by every tab, so section headers, run
// stacks, empty states and count chips look the same everywhere.

import { TEXT_ACTION } from '../shared/chipStyles'

// The one heading style for every panel and region in every tab, so a panel
// reads the same whether it's Verdict's scope or the Policy Editor's output.
// Actions (Save, Expand, Presets…) sit after the closing rule rather than in
// a second header row, keeping the label centred on the rule either way.
export function SectionLabel({ children, actions }: { children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="flex w-full items-center gap-3">
      <div className="flex min-w-0 flex-1 items-center gap-2 text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase">
        <span className="h-px flex-1 bg-line" />
        <span className="text-center">{children}</span>
        <span className="h-px flex-1 bg-line" />
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center justify-end gap-3">{actions}</div>}
    </div>
  )
}

// Heading over the stack of run cards, shared by Verdict and Flows.
export function ResultsHeader({
  title,
  clearLabel,
  onClear,
}: {
  title: string
  clearLabel?: string
  onClear?: () => void
}) {
  return (
    <div className="flex min-h-[1.75rem] items-center justify-between gap-3 border-b border-line pb-3">
      <h2 className="font-display text-xs font-bold tracking-wider text-ink uppercase">{title}</h2>
      {onClear && (
        <button type="button" onClick={onClear} className={`${TEXT_ACTION} hover:text-drop`}>
          {clearLabel}
        </button>
      )}
    </div>
  )
}

// The "nothing run yet" panel every tab shows before its first result.
export function EmptyState({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-3 border border-line bg-panel p-8 text-center text-ink-dim">
      <p className="font-mono text-2xl text-signal" aria-hidden="true">{'>_'}</p>
      <p className="font-display text-xs tracking-wider text-ink uppercase">{title}</p>
      <p className="mx-auto max-w-md text-xs leading-relaxed">{children}</p>
    </div>
  )
}

export function CountChip({
  label,
  value,
  className,
  filled,
  onClick,
}: {
  label: string
  value: number
  className: string
  // True for the filled (bg-drop/bg-allow) headline chips, whose base text
  // is text-void — the glyph's own "dim" shade has to be void-based there
  // too, or text-ink-faint (tuned for dark/void backgrounds) disappears
  // against a bright solid fill.
  filled?: boolean
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={`Click to learn more about "${label}" flows`}
      className={`group border px-2.5 py-1 text-xs font-medium ${className} cursor-pointer hover:brightness-110 active:scale-98 transition-all flex items-center gap-1.5`}
    >
      <span className="font-semibold">{value}</span>
      <span>{label}</span>
      {/* Deliberately not colored by the chip's own category color — this
          is the one part of the chip that's actually clickable-for-info,
          so it reads as a distinct affordance instead of blending into the
          (non-interactive-looking) count + label. */}
      <span
        className={
          filled
            ? 'rounded-full text-void/50 transition-colors group-hover:text-void group-focus-visible:text-void group-focus-visible:ring-1 group-focus-visible:ring-void'
            : 'rounded-full text-ink-faint transition-colors group-hover:text-signal group-focus-visible:text-signal group-focus-visible:ring-1 group-focus-visible:ring-signal'
        }
      >
        ⓘ
      </span>
    </button>
  )
}
