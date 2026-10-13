// Shared helpers for cross-referencing live cluster pods against policy
// peers and flow/verdict graph nodes — the "ground truth over guesswork"
// pattern used across PolicyGraph, PolicyEditorPanel, VerdictGraph, and
// FlowsGraph.

import { useEffect, useState } from 'react'
import { fetchPods, type Pod } from '../api'

// Volatile labels Kubernetes/controllers stamp on individual pod replicas
// (ReplicaSet/StatefulSet churn) rather than the workload's own identity —
// stripped wherever pods are deduped into stable "entities" or their labels
// are displayed, so replica churn doesn't drown out the labels that matter.
export const VOLATILE_LABEL_KEYS = new Set([
  'pod-template-hash',
  'pod-template-generation', // DaemonSet's equivalent of pod-template-hash
  'controller-revision-hash',
  'statefulset.kubernetes.io/pod-name',
  'apps.kubernetes.io/pod-index',
  'batch.kubernetes.io/job-name',
  'job-name',
])

export function nonVolatileLabels(labels: Record<string, string>): [string, string][] {
  return Object.entries(labels).filter(([k]) => !VOLATILE_LABEL_KEYS.has(k))
}

// A pod's non-volatile labels, as a plain object — used to dedupe pod
// replicas of the same workload into one pickable "entity".
export function workloadSignature(labels: Record<string, string>): Record<string, string> {
  const sig: Record<string, string> = {}
  for (const [k, v] of nonVolatileLabels(labels)) sig[k] = v
  return sig
}

// Picks one representative label (preferring well-known workload-identity
// keys) to stand in for a whole signature when a rule peer needs exactly
// one matchLabels entry.
export function primaryLabel(sig: Record<string, string>): [string, string] | null {
  for (const key of ['app.kubernetes.io/name', 'app', 'k8s-app', 'name']) {
    if (sig[key]) return [key, sig[key]]
  }
  const first = Object.entries(sig)[0]
  return first ?? null
}

export function podMatchesSelector(
  podLabels: Record<string, string>,
  selector: Record<string, string>
): boolean {
  const entries = Object.entries(selector).filter(([k]) => k.trim())
  if (entries.length === 0) return false
  return entries.every(([k, v]) => podLabels[k] === v)
}

// Dedupes a namespace's live pods into distinct workload "entities" by
// non-volatile label signature — e.g. 3 replicas of the same Deployment
// collapse into one pickable group instead of 3 near-identical rows.
export function groupPodsBySignature(pods: Pod[]): { signature: Record<string, string>; count: number }[] {
  const map = new Map<string, { signature: Record<string, string>; count: number }>()
  for (const pod of pods) {
    const sig = workloadSignature(pod.labels)
    if (Object.keys(sig).length === 0) continue
    const key = JSON.stringify(sig)
    const existing = map.get(key)
    if (existing) {
      existing.count += 1
    } else {
      map.set(key, { signature: sig, count: 1 })
    }
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count)
}

// Fetches and caches live pods for each distinct namespace referenced by the
// current selection, so the UI can show ground-truth cluster labels instead
// of just a typed-in selector or a flow's bare "namespace/pod" string.
export function useNamespacePods(namespaces: string[]) {
  const [byNamespace, setByNamespace] = useState<Record<string, Pod[]>>({})
  const [loading, setLoading] = useState(false)
  const key = namespaces.join(',')

  useEffect(() => {
    const toFetch = namespaces.filter((ns) => ns && !(ns in byNamespace))
    if (toFetch.length === 0) return
    let cancelled = false
    setLoading(true)
    Promise.all(
      toFetch.map((ns) =>
        fetchPods(ns)
          .then((res): [string, Pod[]] => [ns, res.pods])
          .catch((): [string, Pod[]] => [ns, []])
      )
    ).then((results) => {
      if (cancelled) return
      setByNamespace((prev) => {
        const next = { ...prev }
        for (const [ns, pods] of results) next[ns] = pods
        return next
      })
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  return { byNamespace, loading }
}

// Flow/verdict graph node labels carry "namespace/pod-name" for real pods
// (see the backend's endpointString in flows.go); reserved identities
// (reserved:host, reserved:world, …) and bare IPs never contain exactly one
// "/", so this doubles as a pod-vs-other check.
export function parseNamespacePod(label: string): { namespace: string; podName: string } | null {
  const parts = label.split('/')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null
  return { namespace: parts[0], podName: parts[1] }
}
