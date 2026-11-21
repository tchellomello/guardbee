// Small presentational pieces shared by the Verdict and connectivity-test
// views, so section headers and count chips look the same everywhere.

export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase w-full">
      <span className="h-px flex-1 bg-line" />
      {children}
      <span className="h-px flex-1 bg-line" />
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
