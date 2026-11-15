import type { Flow, VerdictRow } from '../api'
import { parseNamespacePod } from './podLabels'
import { selectableLabels } from './workloadException'

// The flow filter shared by the Flows and Verdict tabs: the UI side of the
// CLI's --pod/--from-*/--to-*/--verdict/--drop-reason-desc/--type flags (flowFilter in
// flows.go). Applied in Hubble's GetFlows query, not to rows already
// fetched, so a re-run is needed to change it — and every one of the Last
// flows then matches.

export interface FlowFilter {
  // --pod: this pod on either side, source or destination.
  pod: string
  fromPod: string
  fromLabel: string
  fromIp: string
  toPod: string
  toService: string
  toLabel: string
  toIp: string
  toPort: string
  // The flow's observed (Hubble) verdict and drop reason, not a simulated one.
  verdict: string
  dropReason: string
  // --type: Hubble's event type (policy-verdict, drop, trace, …).
  type: string
}

export const EMPTY_FLOW_FILTER: FlowFilter = {
  pod: '',
  fromPod: '',
  fromLabel: '',
  fromIp: '',
  toPod: '',
  toService: '',
  toLabel: '',
  toIp: '',
  toPort: '',
  verdict: '',
  dropReason: '',
  type: '',
}

// The query/body parameter names ui.go's flowFilterParams reads.
export type FlowFilterParams = Partial<Record<keyof FlowFilter, string[]>>

// Fields whose value is always exactly one item: a label selector can
// contain commas itself ("app=db,tier=backend" is one selector meaning both
// labels). Every other field accepts several values separated by commas or
// spaces (ORed, like a repeated hubble flag), since pod/service names,
// IPs/CIDRs, ports and enum names can't contain either.
export const SINGLE_VALUE_FIELDS: ReadonlySet<keyof FlowFilter> = new Set(['fromLabel', 'toLabel'])

function splitList(v: string): string[] {
  return v.split(/[\s,]+/).filter(Boolean)
}

export function flowFilterParams(f: FlowFilter): FlowFilterParams {
  const out: FlowFilterParams = {}
  for (const key of Object.keys(EMPTY_FLOW_FILTER) as (keyof FlowFilter)[]) {
    const raw = f[key] ?? ''
    const vals = SINGLE_VALUE_FIELDS.has(key) ? [raw.trim()].filter(Boolean) : splitList(raw)
    if (vals.length) out[key] = vals
  }
  return out
}

export function isFlowFilterEmpty(f: FlowFilter | undefined): boolean {
  return !f || Object.keys(flowFilterParams(f)).length === 0
}

// One-line summary for a run card, e.g. "from label reserved:world · to port 443 · DROPPED".
export function describeFlowFilter(f: FlowFilter): string {
  const p = flowFilterParams(f)
  const list = (k: keyof FlowFilter) => p[k]?.join(', ')
  return [
    p.pod && `pod ${list('pod')}`,
    p.fromPod && `from pod ${list('fromPod')}`,
    p.fromLabel && `from label ${list('fromLabel')}`,
    p.fromIp && `from ${list('fromIp')}`,
    p.toPod && `to pod ${list('toPod')}`,
    p.toService && `to service ${list('toService')}`,
    p.toLabel && `to label ${list('toLabel')}`,
    p.toIp && `to ${list('toIp')}`,
    p.toPort && `port ${list('toPort')}`,
    p.verdict && list('verdict'),
    p.dropReason && `reason ${list('dropReason')}`,
    p.type && `type ${list('type')}`,
  ]
    .filter(Boolean)
    .join(' · ')
}

// For EventSource's GET query string: repeated keys, which ui.go reads as
// q["toPod"] etc.
export function appendFlowFilter(params: URLSearchParams, f: FlowFilter): void {
  for (const [key, vals] of Object.entries(flowFilterParams(f))) {
    for (const v of vals as string[]) params.append(key, v)
  }
}

export type FilterSuggestions = Partial<Record<keyof FlowFilter, string[]>>

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

// Counts candidate values per field, most-seen first.
function tally() {
  const tallies = new Map<keyof FlowFilter, Map<string, number>>()
  return {
    add(field: keyof FlowFilter, v: string, n = 1) {
      const m = tallies.get(field) ?? new Map<string, number>()
      m.set(v, (m.get(v) ?? 0) + n)
      tallies.set(field, m)
    },
    // An endpoint as rendered in a row: "ns/pod" or a "reserved:…" entity.
    addEndpoint(side: 'from' | 'to', endpoint: string, labels: string[] | undefined, n: number) {
      const pod = parseNamespacePod(endpoint)
      if (pod) {
        const prefix = `${pod.namespace}/${workloadPodPrefix(pod.podName)}`
        for (const field of [`${side}Pod`, 'pod'] as const) {
          this.add(field, prefix, n)
          if (prefix !== endpoint) this.add(field, endpoint, n)
        }
      } else if (endpoint.startsWith('reserved:') && !labels?.includes(endpoint)) {
        this.add(`${side}Label`, endpoint, n)
      }
      for (const l of labels ?? []) if (l.startsWith('reserved:')) this.add(`${side}Label`, l, n)
      for (const [k, v] of selectableLabels(labels)) this.add(`${side}Label`, `k8s:${k}=${v}`, n)
    },
    ranked(): FilterSuggestions {
      const out: FilterSuggestions = {}
      for (const [field, m] of tallies) {
        out[field] = [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([v]) => v)
      }
      return out
    },
  }
}

// Values seen in already-judged Verdict rows, as values the filter fields
// accept. Built from rows the UI already has (no extra Hubble query), so it
// only knows what earlier runs returned: changed rows, plus UNCHANGED ones
// when "Show unchanged" was on.
export function filterSuggestions(rows: VerdictRow[]): FilterSuggestions {
  const t = tally()
  for (const r of rows) {
    const n = r.count || 1
    t.addEndpoint('from', r.source, r.sourceLabels, n)
    t.addEndpoint('to', r.destination, r.destinationLabels, n)
    if (r.destinationService) t.add('toService', r.destinationService, n)
    if (r.port > 0) t.add('toPort', String(r.port), n)
  }
  return t.ranked()
}

// The same from the Flows tab's rows, which also carry what was observed:
// verdicts and drop reasons seen are offered too.
export function flowSuggestions(flows: Flow[]): FilterSuggestions {
  const t = tally()
  for (const f of flows) {
    t.addEndpoint('from', f.source, f.sourceLabels, 1)
    t.addEndpoint('to', f.destination, f.destinationLabels, 1)
    const port = /^(?:TCP|UDP):(\d+)$/.exec(f.l4)?.[1]
    if (port && port !== '0') t.add('toPort', port)
    if (f.verdict) t.add('verdict', f.verdict)
    if (f.dropReason) t.add('dropReason', f.dropReason)
  }
  return t.ranked()
}

// The token being typed: the whole value for a single-value field, or the
// text after the last comma in a list field ("443, 54" → "54").
function splitHead(current: string, multi: boolean): { head: string; token: string } {
  if (!multi) return { head: '', token: current.trim() }
  const cut = current.lastIndexOf(',')
  return cut >= 0
    ? { head: current.slice(0, cut + 1).trimEnd() + ' ', token: current.slice(cut + 1).trim() }
    : { head: '', token: current.trim() }
}

// Suggestions for what's being typed, best first: values starting with the
// token, then values containing it anywhere (so "web" finds "app/web-" and
// "k8s:app=web"), case-insensitive. In a list field, values already in the
// list aren't offered again. An empty token offers the most-seen values.
export function matchSuggestions(current: string, suggestions: string[], multi: boolean, limit = 8): string[] {
  const { head, token } = splitHead(current, multi)
  const taken = new Set(splitList(head))
  const t = token.toLowerCase()
  const pool = suggestions.filter((s) => !taken.has(s) && s !== token)
  if (!t) return pool.slice(0, limit)
  const starts = pool.filter((s) => s.toLowerCase().startsWith(t))
  const contains = pool.filter((s) => !s.toLowerCase().startsWith(t) && s.toLowerCase().includes(t))
  return [...starts, ...contains].slice(0, limit)
}

// The field's new value after picking a suggestion: it replaces the token
// being typed, keeping the rest of a list.
export function completeToken(current: string, picked: string, multi: boolean): string {
  return splitHead(current, multi).head + picked
}
