import type { VerdictRow } from '../api'
import { parseNamespacePod } from './podLabels'
import { selectableLabels } from './workloadException'

// The Verdict form's destination filter: the UI side of the verdict
// subcommand's --to-pod/--to-service/--to-label/--to-port (destinationFilter
// in flows.go). Applied in Hubble's GetFlows query, not to rows already
// judged, so a re-run is needed to change it.

export interface DestinationFilter {
  toPod: string
  toService: string
  toLabel: string
  toPort: string
}

export const EMPTY_DESTINATION_FILTER: DestinationFilter = { toPod: '', toService: '', toLabel: '', toPort: '' }

export interface DestinationFilterParams {
  toPod?: string[]
  toService?: string[]
  toLabel?: string[]
  toPort?: string[]
}

// Pod/service names and ports can't contain commas or spaces, so those
// fields accept several values that way (ORed, like a repeated hubble flag).
// A label selector can: "app=db,tier=backend" is one selector meaning both
// labels, so the label field is always exactly one selector.
function splitList(v: string): string[] {
  return v.split(/[\s,]+/).filter(Boolean)
}

export function destinationFilterParams(f: DestinationFilter): DestinationFilterParams {
  const out: DestinationFilterParams = {}
  const pods = splitList(f.toPod)
  const services = splitList(f.toService)
  const ports = splitList(f.toPort)
  const label = f.toLabel.trim()
  if (pods.length) out.toPod = pods
  if (services.length) out.toService = services
  if (label) out.toLabel = [label]
  if (ports.length) out.toPort = ports
  return out
}

export function isDestinationFilterEmpty(f: DestinationFilter | undefined): boolean {
  return !f || Object.keys(destinationFilterParams(f)).length === 0
}

// One-line summary for a run card, e.g. "pod db · port 443, 5432".
export function describeDestinationFilter(f: DestinationFilter): string {
  const p = destinationFilterParams(f)
  return [
    p.toPod && `pod ${p.toPod.join(', ')}`,
    p.toService && `service ${p.toService.join(', ')}`,
    p.toLabel && `label ${p.toLabel[0]}`,
    p.toPort && `port ${p.toPort.join(', ')}`,
  ]
    .filter(Boolean)
    .join(' · ')
}

// For EventSource's GET query string: repeated keys, which ui.go reads as
// q["toPod"] etc.
export function appendDestinationFilter(params: URLSearchParams, f: DestinationFilter): void {
  for (const [key, vals] of Object.entries(destinationFilterParams(f))) {
    for (const v of vals as string[]) params.append(key, v)
  }
}

export type FilterSuggestions = Record<keyof DestinationFilter, string[]>

// Hubble's --to-pod matches a name *prefix*, so the useful suggestion is the
// workload's, not one replica's name: "ns/web-" catches every replica and
// survives a rollout. Strips a Deployment's "-<rs hash>-<pod hash>", a
// DaemonSet's "-<hash>", or a StatefulSet's "-<ordinal>", keeping the dash so
// "web-" doesn't match "webhook-…". A guess from the name alone (a sibling
// "web-admin-…" would still match), so the full pod name is offered too.
export function workloadPodPrefix(podName: string): string {
  for (const re of [/-[a-z0-9]{6,10}-[a-z0-9]{5}$/, /-[a-z0-9]{5}$/, /-\d+$/]) {
    if (re.test(podName)) return podName.replace(re, '-')
  }
  return podName
}

// Destinations seen in already-judged rows, most-seen first, as values the
// filter fields accept. Built from the rows the UI already has (no extra
// Hubble query), so it only knows what earlier runs returned: changed rows,
// plus UNCHANGED ones when "Show unchanged" was on.
export function filterSuggestions(rows: VerdictRow[]): FilterSuggestions {
  const tallies: Record<keyof DestinationFilter, Map<string, number>> = {
    toPod: new Map(),
    toService: new Map(),
    toLabel: new Map(),
    toPort: new Map(),
  }
  const add = (field: keyof DestinationFilter, v: string, n: number) =>
    tallies[field].set(v, (tallies[field].get(v) ?? 0) + n)

  for (const r of rows) {
    const n = r.count || 1
    const pod = parseNamespacePod(r.destination)
    if (pod) {
      const prefix = `${pod.namespace}/${workloadPodPrefix(pod.podName)}`
      add('toPod', prefix, n)
      if (prefix !== r.destination) add('toPod', r.destination, n)
    }
    if (r.destinationService) add('toService', r.destinationService, n)
    for (const l of r.destinationLabels ?? []) {
      if (l.startsWith('reserved:')) add('toLabel', l, n)
    }
    for (const [k, v] of selectableLabels(r.destinationLabels)) add('toLabel', `k8s:${k}=${v}`, n)
    if (r.port > 0) add('toPort', String(r.port), n)
  }

  const ranked = (m: Map<string, number>) =>
    [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([v]) => v)
  return {
    toPod: ranked(tallies.toPod),
    toService: ranked(tallies.toService),
    toLabel: ranked(tallies.toLabel),
    toPort: ranked(tallies.toPort),
  }
}

// A native <datalist> only completes the whole input value, so for the
// comma-separated fields each option is the text already typed up to the
// last comma plus a suggestion: picking one appends instead of replacing.
// Values already in the list aren't offered again.
export function suggestionOptions(current: string, suggestions: string[], multi: boolean): string[] {
  if (!multi) return suggestions
  const cut = current.lastIndexOf(',')
  const head = cut >= 0 ? current.slice(0, cut + 1).trimEnd() + ' ' : ''
  const taken = new Set(splitList(head))
  return suggestions.filter((s) => !taken.has(s)).map((s) => head + s)
}
