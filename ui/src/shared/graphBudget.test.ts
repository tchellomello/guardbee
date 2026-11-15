import { describe, expect, it } from 'vitest'
import {
  GRAPH_EDGE_LIMIT,
  GRAPH_NODE_LIMIT,
  LIVE_GRAPH_RUN_LIMIT,
  graphTooLarge,
  runsWithLiveGraphs,
} from './graphBudget'

describe('graphTooLarge', () => {
  it('allows graphs at the limits', () => {
    expect(graphTooLarge(GRAPH_NODE_LIMIT, GRAPH_EDGE_LIMIT)).toBe(false)
  })

  it('trips on either nodes or edges', () => {
    expect(graphTooLarge(GRAPH_NODE_LIMIT + 1, 0)).toBe(true)
    expect(graphTooLarge(2, GRAPH_EDGE_LIMIT + 1)).toBe(true)
  })
})

describe('runsWithLiveGraphs', () => {
  it('keeps only the newest expanded runs', () => {
    const runs = Array.from({ length: LIVE_GRAPH_RUN_LIMIT + 2 }, (_, i) => ({ id: `r${i}` }))
    const live = runsWithLiveGraphs(runs)
    expect(live.size).toBe(LIVE_GRAPH_RUN_LIMIT)
    expect(live.has('r0')).toBe(true)
    expect(live.has(`r${LIVE_GRAPH_RUN_LIMIT}`)).toBe(false)
  })

  it("doesn't spend a slot on a collapsed run", () => {
    const live = runsWithLiveGraphs([
      { id: 'a', isCollapsed: true },
      { id: 'b' },
      { id: 'c' },
      { id: 'd' },
    ])
    expect([...live]).toEqual(['b', 'c', 'd'])
  })
})
