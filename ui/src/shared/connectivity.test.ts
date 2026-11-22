import { describe, expect, it } from 'vitest'
import type { ConnectionProbeResponse, VerdictResponse } from '../api'
import { candidateFingerprint, connectivityDecision, serviceHostSuggestions, servicePortFor, shortenMiddle } from './connectivity'
import { ConnectionProbeError } from '../api'

const simulation: VerdictResponse = {
  namespace: 'test', candidateRuleCount: 1, baselineRuleCount: 1, flowsRequested: 1, flowsSampled: 1,
  counts: { unchanged: 1, newlyDropped: 0, newlyAllowed: 0, l7Changed: 0, notSimulated: 0, replySkipped: 0, total: 1 },
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

describe('service host suggestions', () => {
  const services = [
    { namespace: 'ai', name: 'ollama', ports: [{ port: 11434, protocol: 'TCP' }] },
    { namespace: 'postgres', name: 'postgres', ports: [{ port: 5432, protocol: 'TCP' }, { port: 9187, protocol: 'UDP' }] },
  ]
  it('lists cluster Services as DNS names, the scope namespace first', () => {
    expect(serviceHostSuggestions(services, [], 'postgres')).toEqual([
      'postgres.postgres.svc.cluster.local',
      'ollama.ai.svc.cluster.local',
    ])
  })
  it('falls back to Services seen in flows, deduplicated', () => {
    expect(serviceHostSuggestions([], ['ai/ollama', 'ai/ollama', 'bogus'], '')).toEqual(['ollama.ai.svc.cluster.local'])
  })
  it("fills the picked Service's port for the protocol, else leaves it", () => {
    expect(servicePortFor(services, 'ollama.ai.svc.cluster.local', 'TCP')).toBe('11434')
    expect(servicePortFor(services, 'postgres.postgres.svc.cluster.local', 'UDP')).toBe('9187')
    expect(servicePortFor(services, 'ollama.ai.svc.cluster.local', 'UDP')).toBeNull()
    expect(servicePortFor(services, '10.0.0.1', 'TCP')).toBeNull()
  })
})
