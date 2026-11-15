// Limits on how much graph the UI draws by default. Each React Flow node and
// edge is real DOM (labels, handles, SVG paths) kept alive for as long as the
// run card is on screen — a big --follow sample or a stack of runs can grow
// that into hundreds of MB and a frozen tab. Past a limit the graph is not
// drawn and the user is asked to narrow the sample instead. "Draw anyway"
// always stays available, and the table below every graph still lists every
// row, so nothing is hidden, only not drawn.
//
// The numbers are deliberately conservative starting points, not measured
// cliffs: a graph past them is already too dense to read, which is the
// better reason to narrow it than memory alone.

export const GRAPH_NODE_LIMIT = 150
export const GRAPH_EDGE_LIMIT = 300

// Stacked runs (Flows' "Stack runs", every Verdict run) each keep their own
// graph instance. Only the newest few expanded runs draw theirs; older ones
// show a "Show graph" placeholder instead.
export const LIVE_GRAPH_RUN_LIMIT = 3

export function graphTooLarge(nodes: number, edges: number): boolean {
  return nodes > GRAPH_NODE_LIMIT || edges > GRAPH_EDGE_LIMIT
}

// Which runs (by id) may draw their graph automatically: the first
// LIVE_GRAPH_RUN_LIMIT expanded runs, in display order (newest first).
// Collapsed runs draw nothing, so they don't use up a slot.
export function runsWithLiveGraphs(runs: { id: string; isCollapsed?: boolean }[]): Set<string> {
  const live = new Set<string>()
  for (const run of runs) {
    if (live.size >= LIVE_GRAPH_RUN_LIMIT) break
    if (!run.isCollapsed) live.add(run.id)
  }
  return live
}
