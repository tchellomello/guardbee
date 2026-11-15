// Shown in place of a graph that isn't drawn: either the graph itself is over
// the size limit (tooLarge) or an older stacked run is past the live-graph
// limit (paused). See shared/graphBudget.ts for why and the limits.

import { GRAPH_EDGE_LIMIT, GRAPH_NODE_LIMIT, LIVE_GRAPH_RUN_LIMIT } from '../shared/graphBudget'

export function GraphPlaceholder({
  reason,
  nodes,
  edges,
  hints,
  onDraw,
}: {
  reason: 'tooLarge' | 'paused'
  nodes?: number
  edges?: number
  // Tab-specific ways to shrink the sample, named after the visible controls.
  hints?: string[]
  onDraw: () => void
}) {
  return (
    <div
      role="status"
      className="flex flex-col gap-2 border border-line bg-void px-4 py-3 text-xs text-ink-dim"
    >
      {reason === 'tooLarge' ? (
        <>
          <p className="text-ink">
            Graph not drawn: <span className="font-mono">{nodes}</span> nodes and{' '}
            <span className="font-mono">{edges}</span> edges is more than this page draws by default (
            {GRAPH_NODE_LIMIT} nodes / {GRAPH_EDGE_LIMIT} edges). A graph that large is hard to read and can slow
            down or crash the browser tab.
          </p>
          {hints && hints.length > 0 && (
            <p>
              Narrow the sample instead: {hints.join('; ')}. The table below still lists every row.
            </p>
          )}
        </>
      ) : (
        <p>
          Graph paused for this older run to save memory. Only the newest {LIVE_GRAPH_RUN_LIMIT} expanded runs
          draw their graph automatically; collapse or remove runs you're done with.
        </p>
      )}
      <button
        type="button"
        onClick={onDraw}
        className="cursor-pointer self-start border border-line px-2.5 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:border-signal hover:text-signal"
      >
        {reason === 'tooLarge' ? 'Draw anyway' : 'Show graph'}
      </button>
    </div>
  )
}
