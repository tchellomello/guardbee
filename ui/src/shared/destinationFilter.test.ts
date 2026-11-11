import { describe, expect, it } from 'vitest'
import type { VerdictRow } from '../api'
import {
  appendDestinationFilter,
  filterSuggestions,
  suggestionOptions,
  workloadPodPrefix,
  describeDestinationFilter,
  destinationFilterParams,
  EMPTY_DESTINATION_FILTER,
  isDestinationFilterEmpty,
} from './destinationFilter'

describe('destinationFilterParams', () => {
  it('omits blank fields', () => {
    expect(destinationFilterParams({ ...EMPTY_DESTINATION_FILTER, toPort: '  ' })).toEqual({})
    expect(isDestinationFilterEmpty(EMPTY_DESTINATION_FILTER)).toBe(true)
    expect(isDestinationFilterEmpty(undefined)).toBe(true)
  })

  it('splits pods, services and ports on commas and spaces', () => {
    expect(
      destinationFilterParams({ toPod: 'db, other/cache', toService: 'api', toLabel: '', toPort: '443 5432,' })
    ).toEqual({ toPod: ['db', 'other/cache'], toService: ['api'], toPort: ['443', '5432'] })
  })

  it('keeps a label selector whole, commas included', () => {
    expect(destinationFilterParams({ ...EMPTY_DESTINATION_FILTER, toLabel: ' k8s:app=db,k8s:tier=backend ' })).toEqual({
      toLabel: ['k8s:app=db,k8s:tier=backend'],
    })
  })
})

describe('describeDestinationFilter', () => {
  it('summarizes the set fields', () => {
    expect(describeDestinationFilter({ toPod: 'db', toService: '', toLabel: 'reserved:kube-apiserver', toPort: '443' })).toBe(
      'pod db · label reserved:kube-apiserver · port 443'
    )
  })
})

describe('appendDestinationFilter', () => {
  it('repeats keys for multiple values', () => {
    const p = new URLSearchParams()
    appendDestinationFilter(p, { ...EMPTY_DESTINATION_FILTER, toPort: '443,80' })
    expect(p.getAll('toPort')).toEqual(['443', '80'])
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

describe('suggestionOptions', () => {
  it('appends to a comma-separated list and skips values already in it', () => {
    expect(suggestionOptions('443, ', ['443', '5432'], true)).toEqual(['443, 5432'])
    expect(suggestionOptions('', ['443'], true)).toEqual(['443'])
  })
  it('replaces the whole value for single-value fields', () => {
    expect(suggestionOptions('k8s:a', ['k8s:app=db'], false)).toEqual(['k8s:app=db'])
  })
})
