import { describe, expect, it } from 'vitest'
import type { ConnectionProbeResponse, VerdictResponse } from '../api'
import { candidateFingerprint, connectivityDecision, shortenMiddle } from './connectivity'
import { ConnectionProbeError } from '../api'

const simulation: VerdictResponse = {
  namespace: 'test', candidateRuleCount: 1, baselineRuleCount: 1, flowsRequested: 1, flowsSampled: 1,
  counts: { unchanged: 1, newlyDropped: 0, newlyAllowed: 0, notSimulated: 0, replySkipped: 0, total: 1 },
  rows: [{ change: 'UNCHANGED', source: 'a', destination: 'b', protocol: 'TCP', port: 80, count: 1, explanation: '', baselineAllowed: false, candidateAllowed: false }],
}
const response: ConnectionProbeResponse = { namespace: 'test', pod: 'a', host: 'b', port: 80, message: '', flows: [{ source: 'a', destination: 'b', time: '', l4: 'TCP:80', verdict: 'DROPPED' }], simulation }

describe('connectivity evidence display', () => {
  it('classifies only known pre-injection rejections as definitely not started', () => {
    for (const status of [400, 403, 405, 409, 413, 415, 429]) {
      const error = new ConnectionProbeError('rejected', status)
      expect(error.status).toBe(status)
      expect(error.definiteRejection).toBe(true)
    }
    for (const status of [404, 500, 502, 504]) expect(new ConnectionProbeError('uncertain', status).definiteRejection).toBe(false)
  })
  it('uses explicit booleans, never UNCHANGED as allow', () => {
    expect(connectivityDecision(response, 'candidateAllowed')).toBe('BLOCKED')
    expect(connectivityDecision(response, 'baselineAllowed')).toBe('BLOCKED')
    expect(connectivityDecision({ ...response, simulation: { ...simulation, rows: [{ ...simulation.rows[0], candidateAllowed: true }] } }, 'candidateAllowed')).toBe('ALLOWED')
  })
  it('withholds universal decisions for missing, partial, skipped, or mixed evidence', () => {
    for (const result of [
      { ...response, flows: [] }, { ...response, simulation: undefined },
      { ...response, simulation: { ...simulation, rows: [] } },
      { ...response, simulation: { ...simulation, flowsSampled: 0 } },
      { ...response, simulation: { ...simulation, skippedPolicies: ['node-selector'] } },
      { ...response, simulation: { ...simulation, counts: { ...simulation.counts, notSimulated: 1 } } },
      { ...response, simulation: { ...simulation, rows: [{ ...simulation.rows[0], candidateAllowed: undefined }] } },
      { ...response, simulation: { ...simulation, rows: [...simulation.rows, { ...simulation.rows[0], candidateAllowed: true }] } },
    ]) expect(connectivityDecision(result, 'candidateAllowed')).toBe('INCONCLUSIVE')
  })
  it('fingerprints exact YAML deterministically for snapshot context', () => {
    expect(candidateFingerprint('candidate')).toBe(candidateFingerprint('candidate'))
    expect(candidateFingerprint('candidate\n')).not.toBe(candidateFingerprint('candidate'))
    expect(candidateFingerprint('')).toMatch(/^[0-9a-f]{8}$/)
  })
})

describe('shortenMiddle', () => {
  it('keeps short names and both ends of long ones', () => {
    expect(shortenMiddle('webapp/webapp-1')).toBe('webapp/webapp-1')
    const short = shortenMiddle('testing2/server-5ccfcf7b88-hvh26')
    expect(short).toHaveLength(20)
    expect(short.startsWith('testing2/')).toBe(true)
    expect(short.endsWith('-hvh26')).toBe(true)
  })
})
