import { describe, expect, it } from 'vitest'
import type { Flow, VerdictRow } from '../api'
import {
  appendFlowFilter,
  filterSuggestions,
  flowSuggestions,
  matchSuggestions,
  completeToken,
  workloadPodPrefix,
  describeFlowFilter,
  flowFilterParams,
  EMPTY_FLOW_FILTER,
  isFlowFilterEmpty,
} from './flowFilter'

describe('flowFilterParams', () => {
  it('omits blank fields', () => {
    expect(flowFilterParams({ ...EMPTY_FLOW_FILTER, toPort: '  ' })).toEqual({})
    expect(isFlowFilterEmpty(EMPTY_FLOW_FILTER)).toBe(true)
    expect(isFlowFilterEmpty(undefined)).toBe(true)
  })

  it('splits pods, services and ports on commas and spaces', () => {
    expect(
      flowFilterParams({ ...EMPTY_FLOW_FILTER, toPod: 'db, other/cache', toService: 'api', toPort: '443 5432,' })
    ).toEqual({ toPod: ['db', 'other/cache'], toService: ['api'], toPort: ['443', '5432'] })
  })

  it('keeps a label selector whole, commas included', () => {
    expect(flowFilterParams({ ...EMPTY_FLOW_FILTER, toLabel: ' k8s:app=db,k8s:tier=backend ' })).toEqual({
      toLabel: ['k8s:app=db,k8s:tier=backend'],
    })
  })
})

describe('describeFlowFilter', () => {
  it('summarizes the set fields', () => {
    expect(
      describeFlowFilter({ ...EMPTY_FLOW_FILTER, toPod: 'db', toLabel: 'reserved:kube-apiserver', toPort: '443' })
    ).toBe('to pod db · to label reserved:kube-apiserver · port 443')
    expect(
      describeFlowFilter({ ...EMPTY_FLOW_FILTER, fromLabel: 'reserved:world', fromIp: '10.0.0.0/8', verdict: 'DROPPED', dropReason: 'POLICY_DENIED' })
    ).toBe('from label reserved:world · from 10.0.0.0/8 · DROPPED · reason POLICY_DENIED')
    expect(describeFlowFilter({ ...EMPTY_FLOW_FILTER, pod: 'app/web', type: 'policy-verdict' })).toBe(
      'pod app/web · type policy-verdict'
    )
  })
})

describe('appendFlowFilter', () => {
  it('repeats keys for multiple values', () => {
    const p = new URLSearchParams()
    appendFlowFilter(p, { ...EMPTY_FLOW_FILTER, toPort: '443,80', pod: 'web, db', type: 'policy-verdict' })
    expect(p.getAll('toPort')).toEqual(['443', '80'])
    // ui.go's flowFilterParamsFromQuery reads --pod/--type as pod/type.
    expect(p.getAll('pod')).toEqual(['web', 'db'])
    expect(p.getAll('type')).toEqual(['policy-verdict'])
  })
})

describe('filterSuggestions', () => {
  const row = (over: Partial<VerdictRow>): VerdictRow => ({
    change: 'NEWLY_DROPPED',
    source: 'app/web-1',
    destination: 'app/db-7d9f8c6b4-x2k9p',
    protocol: 'TCP',
    port: 5432,
    count: 1,
    explanation: '',
    ...over,
  })

  it('offers workload prefixes, services, labels and ports, most-seen first', () => {
    const s = filterSuggestions([
      row({ destinationService: 'app/db', destinationLabels: ['k8s:app=db', 'k8s:io.kubernetes.pod.namespace=app'] }),
      row({ destination: 'reserved:kube-apiserver', destinationLabels: ['reserved:kube-apiserver'], port: 443, count: 5 }),
    ])
    expect(s.toPod).toEqual(['app/db-', 'app/db-7d9f8c6b4-x2k9p'])
    expect(s.toService).toEqual(['app/db'])
    expect(s.toLabel).toEqual(['reserved:kube-apiserver', 'k8s:app=db'])
    expect(s.toPort).toEqual(['443', '5432'])
  })

  it('strips StatefulSet ordinals and DaemonSet hashes', () => {
    expect(workloadPodPrefix('postgres-0')).toBe('postgres-')
    expect(workloadPodPrefix('cilium-x7k2p')).toBe('cilium-')
  })
})

describe('matchSuggestions / completeToken', () => {
  const pool = ['app/web-', 'app/web-7d9f8c6b4-x2k9p', 'k8s:app=web', 'reserved:world', 'app/db-0']
  it('ranks prefix matches before substring matches, case-insensitively', () => {
    expect(matchSuggestions('APP/W', pool, false)).toEqual(['app/web-', 'app/web-7d9f8c6b4-x2k9p'])
    expect(matchSuggestions('web', pool, false)).toEqual(['app/web-', 'app/web-7d9f8c6b4-x2k9p', 'k8s:app=web'])
  })
  it('offers the most-seen values for an empty field', () => {
    expect(matchSuggestions('', pool, false, 2)).toEqual(['app/web-', 'app/web-7d9f8c6b4-x2k9p'])
  })
  it('matches only the token after the last comma, skipping values already listed', () => {
    expect(matchSuggestions('443, ', ['443', '5432'], true)).toEqual(['5432'])
    expect(matchSuggestions('443, 54', ['443', '5432'], true)).toEqual(['5432'])
  })
  it('completes the token, keeping the rest of a list', () => {
    expect(completeToken('443, 54', '5432', true)).toBe('443, 5432')
    expect(completeToken('k8s:a', 'k8s:app=db', false)).toBe('k8s:app=db')
  })
})

describe('flowFilterParams (source side, IPs, verdict)', () => {
  it('splits IPs/CIDRs, verdicts and drop reasons, keeps from-label whole', () => {
    expect(
      flowFilterParams({
        ...EMPTY_FLOW_FILTER,
        fromLabel: 'k8s:app=web,k8s:tier=front',
        fromIp: '10.0.0.0/8, 192.168.1.5',
        verdict: 'DROPPED',
        dropReason: 'POLICY_DENIED POLICY_DENY',
      })
    ).toEqual({
      fromLabel: ['k8s:app=web,k8s:tier=front'],
      fromIp: ['10.0.0.0/8', '192.168.1.5'],
      verdict: ['DROPPED'],
      dropReason: ['POLICY_DENIED', 'POLICY_DENY'],
    })
  })
})

describe('source-side suggestions', () => {
  it('offers source workloads and entities from verdict rows', () => {
    const s = filterSuggestions([
      {
        change: 'NEWLY_DROPPED',
        source: 'reserved:world',
        sourceLabels: ['reserved:world'],
        destination: 'app/web-0',
        protocol: 'TCP',
        port: 8080,
        count: 2,
        explanation: '',
      },
    ])
    expect(s.fromLabel).toEqual(['reserved:world'])
    expect(s.toPod).toEqual(['app/web-', 'app/web-0'])
  })
})

describe('flowSuggestions', () => {
  const flow = (over: Partial<Flow>): Flow => ({
    time: '',
    verdict: 'FORWARDED',
    source: 'app/web-7d9f8c6b4-x2k9p',
    destination: 'app/db-0',
    l4: 'TCP:5432',
    ...over,
  })
  it('offers both sides, ports, and the verdicts and drop reasons seen', () => {
    const s = flowSuggestions([
      flow({}),
      flow({ source: 'reserved:world', sourceLabels: ['reserved:world'], destinationLabels: ['k8s:app=db'], verdict: 'DROPPED', dropReason: 'POLICY_DENIED', l4: 'TCP:443' }),
      flow({ l4: 'ICMPv4' }),
    ])
    expect(s.fromPod).toEqual(['app/web-', 'app/web-7d9f8c6b4-x2k9p'])
    expect(s.fromLabel).toEqual(['reserved:world'])
    expect(s.toPod).toEqual(['app/db-', 'app/db-0'])
    // --pod is either side, so it's offered both sides' workloads.
    expect(s.pod).toEqual(['app/db-', 'app/db-0', 'app/web-', 'app/web-7d9f8c6b4-x2k9p'])
    expect(s.toLabel).toEqual(['k8s:app=db']) // identity labels Hubble reported
    expect(s.toPort).toEqual(['443', '5432']) // one each: ties sort alphabetically
    expect(s.verdict).toEqual(['FORWARDED', 'DROPPED'])
    expect(s.dropReason).toEqual(['POLICY_DENIED'])
  })
})
