import type { ClusterService, ConnectionProbeResponse } from '../api'

export type ConnectivityDecision = 'ALLOWED' | 'BLOCKED' | 'INCONCLUSIVE'

// This is a display fingerprint, not a security digest. The full frozen YAML
// is the source of truth, and stale detection always compares that exact text.
export function candidateFingerprint(yaml: string): string {
  let hash = 2166136261
  for (let i = 0; i < yaml.length; i++) hash = Math.imul(hash ^ yaml.charCodeAt(i), 16777619)
  return (hash >>> 0).toString(16).padStart(8, '0')
}

export function connectivityDecision(response: ConnectionProbeResponse, side: 'baselineAllowed' | 'candidateAllowed'): ConnectivityDecision {
  const simulation = response.simulation
  // A change category (especially UNCHANGED) is not an allow decision. Partial
  // capture or an omitted baseline policy must not become a confident headline.
  if (!response.flows?.length || !simulation?.rows?.length || simulation.skippedPolicies?.length ||
    typeof simulation.counts?.notSimulated !== 'number' || simulation.counts.notSimulated > 0 || !simulation.flowsSampled) return 'INCONCLUSIVE'
  if (simulation.rows.some((row) => typeof row.baselineAllowed !== 'boolean' || typeof row.candidateAllowed !== 'boolean')) return 'INCONCLUSIVE'
  const decisions = simulation.rows.map((row) => row[side])
  if (decisions.every((value) => value === true)) return 'ALLOWED'
  if (decisions.every((value) => value === false)) return 'BLOCKED'
  return 'INCONCLUSIVE'
}

// A Service's in-cluster DNS name, what a connectivity test's Host takes.
export function serviceHost(namespace: string, name: string): string {
  return `${name}.${namespace}.svc.cluster.local`
}

// Host suggestions: the cluster's Services (or, when listing them isn't
// allowed, the "ns/name" Services seen in flows), the scope namespace first.
export function serviceHostSuggestions(services: ClusterService[], seen: string[], preferNamespace: string): string[] {
  const refs = services.length
    ? services.map((s) => ({ namespace: s.namespace, name: s.name }))
    : seen.flatMap((ref) => {
        const [namespace, name] = ref.split('/')
        return namespace && name ? [{ namespace, name }] : []
      })
  const first = refs.filter((r) => r.namespace === preferNamespace)
  const rest = refs.filter((r) => r.namespace !== preferNamespace)
  return [...new Set([...first, ...rest].map((r) => serviceHost(r.namespace, r.name)))]
}

// The port to fill in when Host names a known Service: its first port for
// the chosen protocol, or null to leave the Port field alone.
export function servicePortFor(services: ClusterService[], host: string, protocol: string): string | null {
  const svc = services.find((s) => serviceHost(s.namespace, s.name) === host.trim())
  const port = svc?.ports?.find((p) => p.protocol === protocol)
  return port ? String(port.port) : null
}

// Middle-ellipsis for the path diagram's endpoint labels: keeps both the
// namespace prefix and the Pod's unique suffix, which is what tells two
// replicas apart.
export function shortenMiddle(name: string, max = 20): string {
  if (name.length <= max) return name
  const keep = max - 1
  return `${name.slice(0, Math.ceil(keep / 2))}…${name.slice(name.length - Math.floor(keep / 2))}`
}
