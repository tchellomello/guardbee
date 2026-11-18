import type { ConnectionProbeResponse } from '../api'

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
