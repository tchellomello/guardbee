import { describe, expect, it } from 'vitest'
import type { VerdictRow } from '../api'
import {
  appendPolicyDocument,
  buildExceptionPolicyYAML,
  defaultSelectedLabels,
  exceptionTargets,
  selectableLabels,
} from './workloadException'

const gatewayLabels = [
  'k8s:app.kubernetes.io/name=celostar-gateway',
  'k8s:app.kubernetes.io/instance=celostar',
  'k8s:io.kubernetes.pod.namespace=alpha',
  'k8s:io.cilium.k8s.policy.cluster=default',
  'k8s:io.cilium.k8s.policy.serviceaccount=celostar-gateway',
  'k8s:io.cilium.k8s.namespace.labels.kubernetes.io/metadata.name=alpha',
  'k8s:pod-template-hash=547bdfc5b9',
]

const droppedRow: VerdictRow = {
  change: 'NEWLY_DROPPED',
  source: 'alpha/celostar-gateway-547bdfc5b9-jdxx2',
  destination: 'reserved:kube-apiserver',
  protocol: 'TCP',
  port: 443,
  count: 3,
  explanation: '',
  side: 'egress',
  sourceLabels: gatewayLabels,
  destinationLabels: ['reserved:kube-apiserver'],
}

describe('selectableLabels', () => {
  it('keeps pod labels and drops derived/volatile ones', () => {
    expect(selectableLabels(gatewayLabels)).toEqual([
      ['app.kubernetes.io/name', 'celostar-gateway'],
      ['app.kubernetes.io/instance', 'celostar'],
      ['io.cilium.k8s.policy.serviceaccount', 'celostar-gateway'],
    ])
  })
})

describe('exceptionTargets', () => {
  it('targets the source workload for an egress-side drop, with the entity as peer', () => {
    const [t, ...rest] = exceptionTargets(droppedRow)
    expect(rest).toHaveLength(0)
    expect(t.direction).toBe('egress')
    expect(t.subjectNamespace).toBe('alpha')
    expect(t.peer).toEqual({ kind: 'entity', entity: 'kube-apiserver' })
    expect(defaultSelectedLabels(t)).toEqual({ 'app.kubernetes.io/name': 'celostar-gateway' })
  })

  it('targets the destination workload for an ingress-side drop, with a pod peer', () => {
    const row: VerdictRow = {
      ...droppedRow,
      source: 'beta/client-abc',
      sourceLabels: ['k8s:app=client', 'k8s:io.kubernetes.pod.namespace=beta'],
      destination: 'alpha/celostar-gateway-547bdfc5b9-jdxx2',
      destinationLabels: gatewayLabels,
      side: 'ingress',
    }
    const [t] = exceptionTargets(row)
    expect(t.direction).toBe('ingress')
    expect(t.peer).toEqual({ kind: 'pod', namespace: 'beta', label: ['app', 'client'] })
  })

  it('returns nothing for unchanged rows or a non-pod subject', () => {
    expect(exceptionTargets({ ...droppedRow, change: 'UNCHANGED', side: undefined })).toEqual([])
    expect(exceptionTargets({ ...droppedRow, side: 'ingress' })).toEqual([])
  })
})

describe('buildExceptionPolicyYAML', () => {
  const [t] = exceptionTargets(droppedRow)

  it('builds an additive allow that opts out of default-deny', () => {
    const yaml = buildExceptionPolicyYAML(t, defaultSelectedLabels(t), 'allow', 'TCP', 443)
    expect(yaml).toContain('name: guardbee-allow-celostar-gateway-kube-apiserver-443')
    expect(yaml).toContain('namespace: alpha')
    expect(yaml).toContain('app.kubernetes.io/name: "celostar-gateway"')
    expect(yaml).toContain('  egress:\n    - toEntities:\n        - kube-apiserver')
    expect(yaml).toContain('port: "443"')
    expect(yaml).not.toContain('ingress')
    expect(yaml.trimEnd().endsWith('enableDefaultDeny:\n    egress: false')).toBe(true)
  })

  it('builds a deny with exactly one enableDefaultDeny block', () => {
    const yaml = buildExceptionPolicyYAML(t, defaultSelectedLabels(t), 'deny', 'TCP', 443)
    expect(yaml).toContain('  egressDeny:\n    - toEntities:')
    expect(yaml.match(/enableDefaultDeny/g)).toHaveLength(1)
  })

  it('appends as a separate YAML document', () => {
    expect(appendPolicyDocument('a: 1\n\n', 'b: 2\n')).toBe('a: 1\n---\nb: 2\n')
  })
})
