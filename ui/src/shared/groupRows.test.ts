import { describe, expect, it } from 'vitest'
import { groupRows } from './groupRows'
import type { VerdictRow } from '../api'

const row = (over: Partial<VerdictRow> = {}): VerdictRow => ({
  change: 'UNCHANGED',
  source: 'testing/netshoot-mmello',
  destination: 'reserved:world',
  protocol: 'TCP',
  port: 80,
  count: 1,
  explanation: 'same',
  ...over,
})

describe('groupRows', () => {
  it('sums identical patterns and keeps first-seen order', () => {
    const out = groupRows([row(), row({ port: 443 }), row(), row({ count: 3 })])
    expect(out.map((r) => [r.port, r.count])).toEqual([
      [80, 5],
      [443, 1],
    ])
  })

  it('keeps different change, source, destination or protocol apart', () => {
    const out = groupRows([
      row(),
      row({ change: 'NEWLY_DROPPED' }),
      row({ source: 'a/b' }),
      row({ destination: 'reserved:host' }),
      row({ protocol: 'UDP' }),
    ])
    expect(out).toHaveLength(5)
  })

  it('does not mutate its input', () => {
    const input = [row(), row()]
    groupRows(input)
    expect(input.map((r) => r.count)).toEqual([1, 1])
  })
})
