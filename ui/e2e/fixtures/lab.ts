// Mock cluster data modeled on the self-paced Lab (docs/guide/lab.md):
// webapp -> postgres on 5432, a prometheus scrape, kubelet probes from the
// host, and internet traffic dropped by policy. Shaped exactly like the
// JSON the real endpoints return (ui/src/api.ts), so a test failing here
// means the UI broke, not the fixture.

import type { Flow, PolicyListItem, PolicyRef, VerdictResponse, VerdictRow } from '../../src/api'

type Endpoint = [name: string, labels: string[]]

export const EP: Record<'web' | 'pg' | 'prom' | 'host' | 'world', Endpoint> = {
  web: ['webapp/webapp-7d9f8c6b4-x2k9p', ['k8s:app=webapp', 'k8s:io.kubernetes.pod.namespace=webapp']],
  pg: ['postgres/postgres-0', ['k8s:app=postgres', 'k8s:io.kubernetes.pod.namespace=postgres']],
  prom: ['observability/prometheus-5c8d7f9b6-q8w2e', ['k8s:app=prometheus', 'k8s:io.kubernetes.pod.namespace=observability']],
  host: ['reserved:host', ['reserved:host']],
  world: ['reserved:world', ['reserved:world']],
}

function flow(i: number, from: keyof typeof EP, to: keyof typeof EP, l4: string, verdict = 'FORWARDED', dropReason?: string, why: Partial<Flow> = {}): Flow {
  return {
    time: new Date(Date.UTC(2026, 10, 15, 14, 0, i)).toISOString(),
    verdict,
    dropReason,
    source: EP[from][0],
    sourceLabels: EP[from][1],
    destination: EP[to][0],
    destinationLabels: EP[to][1],
    l4,
    ...why,
  }
}

// Policy attribution as blame.go's flowAttribution emits it on a
// policy-verdict event (texts match it exactly). Flows without one stand in
// for other event types (trace), which carry none.
const ref = (kind: string, name: string, namespace?: string): PolicyRef => ({
  kind,
  name,
  namespace,
  display: `${{ CiliumNetworkPolicy: 'CNP:', CiliumClusterwideNetworkPolicy: 'CCNP:' }[kind] ?? kind + ':'}${namespace ? namespace + '/' : ''}${name}`,
})
const ALLOW_WEBAPP = ref('CiliumNetworkPolicy', 'postgres-allow-webapp', 'postgres')
const ALLOW_METRICS = ref('NetworkPolicy', 'allow-metrics', 'postgres')
const LOCKDOWN = ref('CiliumClusterwideNetworkPolicy', 'lockdown')
const allowedBy = (dir: string, r: PolicyRef): Partial<Flow> => ({ direction: dir, decision: 'allowed', allowedBy: [r], decidedBy: `allowed by ${r.display}` })
const DEFAULT_DENY: Partial<Flow> = { direction: 'INGRESS', decision: 'default-deny', decidedBy: 'default deny: no policy rule allows it' }

export const FLOWS: Flow[] = [
  flow(1, 'web', 'pg', 'TCP:5432', 'FORWARDED', undefined, allowedBy('INGRESS', ALLOW_WEBAPP)),
  flow(2, 'prom', 'pg', 'TCP:9187', 'FORWARDED', undefined, allowedBy('INGRESS', ALLOW_METRICS)),
  flow(3, 'host', 'pg', 'TCP:5432', 'FORWARDED', undefined, { direction: 'INGRESS', decision: 'allowed', decidedBy: 'allowed, no policy attributed by Hubble' }),
  flow(4, 'world', 'web', 'TCP:443', 'DROPPED', 'POLICY_DENIED', DEFAULT_DENY),
  flow(5, 'web', 'pg', 'TCP:5432', 'FORWARDED', undefined, allowedBy('INGRESS', ALLOW_WEBAPP)),
  flow(6, 'world', 'web', 'TCP:8080', 'DROPPED', 'POLICY_DENIED', DEFAULT_DENY),
  flow(7, 'prom', 'pg', 'TCP:9187'),
  flow(8, 'world', 'pg', 'TCP:5432', 'DROPPED', 'POLICY_DENY', {
    direction: 'INGRESS',
    decision: 'denied',
    deniedBy: [LOCKDOWN],
    decidedBy: `denied by ${LOCKDOWN.display}`,
  }),
]

// Answers a /api/flows query the way Hubble would for the fields the
// tests exercise, so a filter that reaches the backend visibly narrows the
// result (and one that doesn't, doesn't).
export function answerFlows(url: string): Flow[] {
  const q = new URL(url).searchParams
  const ns = q.get('namespace')
  const any = (key: string, pred: (v: string) => boolean) => q.getAll(key).length === 0 || q.getAll(key).some(pred)
  return FLOWS.filter(
    (f) =>
      (!ns || f.source.startsWith(ns + '/') || f.destination.startsWith(ns + '/')) &&
      any('verdict', (v) => f.verdict === v) &&
      any('dropReason', (v) => f.dropReason === v) &&
      any('fromLabel', (v) => (f.sourceLabels ?? []).includes(v)) &&
      any('toLabel', (v) => (f.destinationLabels ?? []).includes(v)) &&
      any('fromPod', (v) => f.source.startsWith(v)) &&
      any('toPod', (v) => f.destination.startsWith(v)) &&
      any('toPort', (v) => f.l4.endsWith(':' + v)) &&
      any('pod', (v) => f.source.startsWith(v) || f.destination.startsWith(v)) &&
      any('type', (v) => (v === 'policy-verdict') === (f.decision !== undefined))
  )
}

function row(change: VerdictRow['change'], from: keyof typeof EP, to: keyof typeof EP, port: number, count: number): VerdictRow {
  return {
    change,
    source: EP[from][0],
    destination: EP[to][0],
    protocol: 'TCP',
    port,
    count,
    explanation: '',
    side: 'ingress',
    sourceLabels: EP[from][1],
    destinationLabels: EP[to][1],
  }
}

// The Lab's "looks-correct" candidate: allows webapp, so prometheus and the
// host probe are newly dropped.
export const VERDICT: VerdictResponse = {
  namespace: 'postgres',
  candidateRuleCount: 1,
  baselineRuleCount: 0,
  flowsRequested: 50,
  flowsSampled: 32,
  counts: { unchanged: 15, newlyDropped: 17, newlyAllowed: 0, notSimulated: 0, replySkipped: 0, total: 32 },
  rows: [row('NEWLY_DROPPED', 'prom', 'pg', 9187, 6), row('NEWLY_DROPPED', 'host', 'pg', 5432, 11), row('UNCHANGED', 'web', 'pg', 5432, 15)],
  context: 'kind-guardbee-lab',
}

export const LOOKS_CORRECT_CNP = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: postgres-allow-webapp
  namespace: postgres
spec:
  endpointSelector:
    matchLabels:
      app: postgres
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: webapp
            app: webapp
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
`

export const NAMESPACES = ['default', 'observability', 'postgres', 'webapp']

export const POLICIES: PolicyListItem[] = [
  {
    kind: 'CiliumNetworkPolicy',
    name: 'postgres-allow-webapp',
    namespace: 'postgres',
    description: 'Lab: webapp may reach postgres',
    ingressRuleCount: 1,
    egressRuleCount: 0,
  },
  { kind: 'CiliumClusterwideNetworkPolicy', name: 'lockdown', ingressRuleCount: 2, egressRuleCount: 1 },
]
