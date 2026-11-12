// Turns a flagged verdict row into a narrow, per-workload exception policy:
// a separate CiliumNetworkPolicy whose endpointSelector is the affected
// workload's own identity labels, allowing or denying just that one
// peer/port. Appended to the candidate as another YAML document, so the
// backend judges candidate + exception together with Cilium's own engine
// (allows union across policies, a deny beats any allow) instead of this UI
// guessing how they combine.

import type { VerdictRow } from '../api'
import { generateCiliumNetworkPolicyYAML, type PolicyModel, type Protocol } from '../policy'
import { VOLATILE_LABEL_KEYS, parseNamespacePod, primaryLabel } from './podLabels'

// reserved:<x> identity labels whose <x> is also a valid toEntities/
// fromEntities value. "cluster"/"all" are entity groupings, never an
// identity's own reserved label, so they can't appear here.
const RESERVED_ENTITIES = new Set([
  'host',
  'remote-node',
  'kube-apiserver',
  'health',
  'init',
  'ingress',
  'unmanaged',
  'world',
  'world-ipv4',
  'world-ipv6',
])

// Labels Cilium derives itself rather than reading off the pod: the
// namespace is already implied by a CNP's own metadata.namespace (and is
// added explicitly for a cross-namespace peer), and namespace-label/cluster
// keys describe where a pod lives, not which workload it is.
function isDerivedKey(key: string): boolean {
  return (
    key === 'io.kubernetes.pod.namespace' ||
    key === 'io.cilium.k8s.policy.cluster' ||
    key.startsWith('io.cilium.k8s.namespace.labels.')
  )
}

// The pod-sourced ("k8s:") identity labels usable in a matchLabels
// selector, minus derived and per-replica volatile keys.
export function selectableLabels(identityLabels: string[] = []): [string, string][] {
  const out: [string, string][] = []
  for (const l of identityLabels) {
    if (!l.startsWith('k8s:')) continue
    const rest = l.slice('k8s:'.length)
    const eq = rest.indexOf('=')
    if (eq <= 0) continue
    const key = rest.slice(0, eq)
    if (isDerivedKey(key) || VOLATILE_LABEL_KEYS.has(key)) continue
    out.push([key, rest.slice(eq + 1)])
  }
  return out
}

export type ExceptionPeer =
  | { kind: 'entity'; entity: string }
  | { kind: 'pod'; namespace: string; label: [string, string] }
  | { kind: 'cidr'; cidr: string }

export interface ExceptionTarget {
  // ingress = the destination workload's policy needs the exception (peer
  // is the source); egress = the source workload's (peer is the destination).
  direction: 'ingress' | 'egress'
  subjectNamespace: string
  subjectPod: string
  subjectLabels: [string, string][]
  peer: ExceptionPeer
  peerDisplay: string
}

function classifyPeer(peer: string, peerLabels: string[] | undefined): ExceptionPeer | null {
  const pod = parseNamespacePod(peer)
  if (pod) {
    const label = primaryLabel(Object.fromEntries(selectableLabels(peerLabels)))
    return label ? { kind: 'pod', namespace: pod.namespace, label } : null
  }
  if (peer.startsWith('reserved:')) {
    const entity = peer.slice('reserved:'.length)
    return RESERVED_ENTITIES.has(entity) ? { kind: 'entity', entity } : null
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(peer)) return { kind: 'cidr', cidr: `${peer}/32` }
  return null
}

// One target per side that actually flipped (per the engine's own `side`),
// skipping any side whose workload isn't a labelled pod (e.g. reserved:host
// can't be a CNP's endpointSelector) or whose peer can't be written as a
// rule peer.
export function exceptionTargets(row: VerdictRow): ExceptionTarget[] {
  if (row.change === 'UNCHANGED' || !row.side) return []
  const directions: ('ingress' | 'egress')[] = row.side === 'both' ? ['egress', 'ingress'] : [row.side]
  const targets: ExceptionTarget[] = []
  for (const direction of directions) {
    const [subject, subjectLabels, peer, peerLabels] =
      direction === 'egress'
        ? [row.source, row.sourceLabels, row.destination, row.destinationLabels]
        : [row.destination, row.destinationLabels, row.source, row.sourceLabels]
    const pod = parseNamespacePod(subject)
    const labels = selectableLabels(subjectLabels)
    const peerSel = classifyPeer(peer, peerLabels)
    if (!pod || labels.length === 0 || !peerSel) continue
    targets.push({
      direction,
      subjectNamespace: pod.namespace,
      subjectPod: pod.podName,
      subjectLabels: labels,
      peer: peerSel,
      peerDisplay: peer,
    })
  }
  return targets
}

// Preselects one well-known workload-identity label, so the default
// exception covers the workload's replicas without also pinning on
// incidental labels.
export function defaultSelectedLabels(target: ExceptionTarget): Record<string, string> {
  const all = Object.fromEntries(target.subjectLabels)
  const primary = primaryLabel(all)
  return primary ? { [primary[0]]: primary[1] } : all
}

function slug(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function peerSlug(peer: ExceptionPeer): string {
  if (peer.kind === 'entity') return peer.entity
  if (peer.kind === 'pod') return peer.label[1]
  return peer.cidr.replace('/32', '')
}

export function buildExceptionPolicyYAML(
  target: ExceptionTarget,
  selector: Record<string, string>,
  action: 'allow' | 'deny',
  protocol: string,
  port: number
): string {
  const workload = slug(Object.values(selector)[0] ?? target.subjectPod)
  const name = slug(`guardbee-${action}-${workload}-${peerSlug(target.peer)}-${port}`).slice(0, 63).replace(/-$/, '')
  const proto: Protocol = protocol === 'TCP' || protocol === 'UDP' ? protocol : 'ANY'
  const toPorts = [{ port: String(port), protocol: proto }]
  const deny = action === 'deny'
  const endpoints =
    target.peer.kind === 'pod'
      ? [{ matchLabels: { [target.peer.label[0]]: target.peer.label[1] }, namespace: target.peer.namespace }]
      : []
  const cidrs = target.peer.kind === 'cidr' ? [target.peer.cidr] : []
  const entities = target.peer.kind === 'entity' ? [target.peer.entity] : []
  const verb = deny ? 'Deny' : 'Allow'

  const model: PolicyModel = {
    kind: 'CiliumNetworkPolicy',
    name,
    namespace: target.subjectNamespace,
    description: `GuardBee exception: ${verb} ${target.direction} ${target.peerDisplay} ${proto}:${port} for ${target.subjectNamespace}/${target.subjectPod}'s workload`,
    targetLabels: selector,
    ingressRules:
      target.direction === 'ingress'
        ? [{ id: 'exception', fromEndpoints: endpoints, fromCIDRs: cidrs, fromEntities: entities, toPorts, deny }]
        : [],
    egressRules:
      target.direction === 'egress'
        ? [{ id: 'exception', toEndpoints: endpoints, toCIDRs: cidrs, toEntities: entities, toServices: [], toPorts, deny }]
        : [],
    egressDenyAll: false,
    // The other direction stays unmanaged — this policy only exists to
    // carve out (or block) one peer/port.
    ingressUnmanaged: true,
  }
  let yaml = generateCiliumNetworkPolicyYAML(model)
  // The generator already opts a deny-only direction out of default-deny.
  // An allow exception needs the same opt-out: its selector may match pods
  // the candidate never selected, and an ordinary allow policy would flip
  // their whole direction to default-deny (confirmed against the vendored
  // engine — verdict_test.go's TestJudgeFlowMultiDocCandidateWithWorkloadException).
  if (!deny) yaml += `  enableDefaultDeny:\n    ${target.direction}: false\n`
  return yaml
}

export function appendPolicyDocument(candidateYAML: string, doc: string): string {
  return `${candidateYAML.trimEnd()}\n---\n${doc}`
}
