// Makes a table cell's source/destination text clickable, selecting the
// matching node in the graph above (Flows or Verdict) — the same isolation
// effect as clicking the box directly, triggered from the row instead.
export function GraphNodeLink({
  selected,
  onClick,
  children,
}: {
  selected: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Select this node in the flow graph above"
      className={`cursor-pointer text-left underline decoration-dotted underline-offset-2 transition-colors hover:text-signal ${
        selected ? 'text-signal font-semibold' : ''
      }`}
    >
      {children}
    </button>
  )
}
