// The flow filter form shared by the Flows and Verdict tabs — the UI side of
// the CLI's --pod/--from-*/--to-*/--verdict/--drop-reason-desc/--type flags (flowFilter in
// flows.go). One component so the two tabs can only ever offer the same
// filters, the way ui.go's flowFilterParams makes them parse the same.
//
// A <details> so the filter stays out of the way until wanted, but opens by
// itself when one is set (e.g. restored after a reload): a filter that's
// active but hidden would make a run look like it saw all traffic.
//
// Each field suggests values from the results below (a native <datalist>:
// type to narrow, or pick from the dropdown), so something seen in the
// results can be filtered on without retyping it.

import { useEffect, useState, type ReactNode } from 'react'
import { fetchFlowFilterOptions, type FlowFilterOptions } from '../api'
import { SuggestInput } from './SuggestInput'
import {
  describeFlowFilter,
  EMPTY_FLOW_FILTER,
  isFlowFilterEmpty,
  SINGLE_VALUE_FIELDS,
  type FilterSuggestions,
  type FlowFilter,
} from '../shared/flowFilter'

// The enum lists never change for a given binary, so one fetch per page load.
let optionsPromise: Promise<FlowFilterOptions> | null = null
function useFlowFilterOptions(): FlowFilterOptions | null {
  const [options, setOptions] = useState<FlowFilterOptions | null>(null)
  useEffect(() => {
    optionsPromise ??= fetchFlowFilterOptions()
    optionsPromise.then(setOptions).catch(() => {
      optionsPromise = null
    })
  }, [])
  return options
}

// The verdicts worth a one-click choice; the rest stay in the dropdown.
const COMMON_VERDICTS = ['FORWARDED', 'DROPPED', 'AUDIT']

// One-click starting points for the questions people actually ask. Each
// only sets its own fields, so they combine with whatever else is set.
const QUICK_FILTERS: { label: string; title: string; set: Partial<FlowFilter> }[] = [
  { label: 'Dropped', title: 'Only flows Cilium dropped', set: { verdict: 'DROPPED' } },
  {
    label: 'Policy drops',
    title: 'Only flows dropped by a network policy (POLICY_DENIED, POLICY_DENY)',
    set: { verdict: 'DROPPED', dropReason: 'POLICY_DENIED, POLICY_DENY' },
  },
  {
    label: 'Policy verdicts',
    title: 'Only policy-verdict events — the ones Cilium attributes to a policy (--type policy-verdict, what `blame` shows)',
    set: { type: 'policy-verdict' },
  },
  { label: 'From the internet', title: 'Only flows from outside the cluster (reserved:world)', set: { fromLabel: 'reserved:world' } },
  { label: 'From nodes', title: 'Only flows from the node itself, e.g. kubelet probes (reserved:host)', set: { fromLabel: 'reserved:host' } },
  { label: 'To the API server', title: 'Only flows to the Kubernetes API server (reserved:kube-apiserver)', set: { toLabel: 'reserved:kube-apiserver' } },
  {
    label: 'L7 requests',
    title: "Only HTTP and DNS records (--type l7) — they exist only for traffic already behind Cilium's proxy",
    set: { type: 'l7' },
  },
]

export function FlowFilterFields({
  filter,
  onChange,
  suggestions,
  intro,
}: {
  filter: FlowFilter
  onChange: (f: FlowFilter) => void
  suggestions: FilterSuggestions
  // One tab-specific sentence on what narrowing means there.
  intro: ReactNode
}) {
  const options = useFlowFilterOptions()
  const active = !isFlowFilterEmpty(filter)
  // Opens by itself when a filter gets set (e.g. restored after a reload, or
  // "Duplicate to form"), but only the user closes it. Deriving `open` from
  // `active` closed the section under the cursor the moment the filter
  // became empty: un-toggling the last quick filter, Clear, or deleting the
  // last character of the only filled field.
  const [open, setOpen] = useState(active)
  const [wasActive, setWasActive] = useState(active)
  if (active !== wasActive) {
    setWasActive(active)
    if (active && !open) setOpen(true)
  }
  const inputClass = (set: boolean) =>
    `w-full border px-2.5 py-1.5 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none ${
      set ? 'border-signal/60 bg-signal/5' : 'border-line bg-void'
    }`

  const input = (
    key: keyof FlowFilter,
    label: string,
    placeholder: string,
    title: string,
    extra: string[] = [],
    wide = false
  ) => {
    const seen = suggestions[key] ?? []
    const pool = [...seen, ...extra.filter((v) => !seen.includes(v))]
    return (
      <label className={`block min-w-0 ${wide ? 'sm:col-span-2' : ''}`} title={title}>
        <span className="mb-1 block text-[0.6rem] font-semibold tracking-[0.1em] text-ink-dim uppercase">{label}</span>
        <SuggestInput
          value={filter[key]}
          onChange={(v) => onChange({ ...filter, [key]: v })}
          suggestions={pool}
          multi={!SINGLE_VALUE_FIELDS.has(key)}
          placeholder={placeholder}
          className={inputClass(filter[key].trim() !== '')}
        />
      </label>
    )
  }

  const verdictChoices = options?.verdicts ?? COMMON_VERDICTS
  // A labeled row: the group name in a left column on wide layouts, above
  // the fields on narrow ones; the fields take as many ~10rem columns as fit.
  const row = (title: string, children: ReactNode) => (
    <div className="grid gap-x-4 gap-y-1.5 sm:grid-cols-[5.5rem_1fr]">
      <div className="pt-[1.15rem] font-display text-[0.7rem] font-bold tracking-wider text-ink uppercase">{title}</div>
      <div className="grid grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-3">{children}</div>
    </div>
  )
  const quickActive = (q: (typeof QUICK_FILTERS)[number]) =>
    Object.entries(q.set).every(([k, v]) => filter[k as keyof FlowFilter] === v)

  return (
    <details
      open={open}
      onToggle={(e) => setOpen(e.currentTarget.open)}
      className="group min-w-0"
    >
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 py-1 text-[0.7rem] font-semibold tracking-[0.12em] text-ink-dim uppercase hover:text-ink">
        <span className="flex min-w-0 items-center gap-2">
          <span className="inline-block transition-transform group-open:rotate-90">▸</span>
          <span>Filters</span>
          {active ? (
            <span className="truncate font-mono text-[0.7rem] normal-case tracking-normal text-signal">
              {describeFlowFilter(filter)}
            </span>
          ) : (
            <span className="normal-case tracking-normal text-ink-faint">— dropped flows, a peer, an IP…</span>
          )}
        </span>
        {active && (
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault()
              onChange(EMPTY_FLOW_FILTER)
            }}
            className="shrink-0 cursor-pointer border border-line px-2 py-0.5 font-display text-[0.6rem] font-bold tracking-wider text-ink-dim hover:border-drop hover:text-drop"
          >
            Clear
          </button>
        )}
      </summary>

      <div className="mt-3 space-y-4 border-l-2 border-signal/30 pl-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[0.65rem] text-ink-faint">Quick:</span>
          {QUICK_FILTERS.map((q) => {
            const on = quickActive(q)
            return (
              <button
                key={q.label}
                type="button"
                title={q.title}
                aria-pressed={on}
                onClick={() => {
                  if (!on) return onChange({ ...filter, ...q.set })
                  const cleared = { ...filter }
                  for (const k of Object.keys(q.set) as (keyof FlowFilter)[]) cleared[k] = ''
                  onChange(cleared)
                }}
                className={`cursor-pointer rounded-full border px-3 py-1 text-[0.7rem] transition-colors ${
                  on
                    ? 'border-signal bg-signal text-void'
                    : 'border-line bg-void text-ink-dim hover:border-signal hover:text-signal'
                }`}
              >
                {q.label}
              </button>
            )
          })}
        </div>

        {row(
          'Observed',
          <>
            <label className="block min-w-0" title="The verdict Cilium gave the flow (--verdict)">
              <span className="mb-1 block text-[0.6rem] font-semibold tracking-[0.1em] text-ink-dim uppercase">Verdict</span>
              <select
                value={filter.verdict}
                onChange={(e) => onChange({ ...filter, verdict: e.target.value })}
                className={inputClass(filter.verdict !== '')}
              >
                <option value="">Any</option>
                {[...COMMON_VERDICTS, ...verdictChoices.filter((v) => !COMMON_VERDICTS.includes(v))].map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
            {input('dropReason', 'Drop reason', 'POLICY_DENIED', 'Why Cilium dropped it (--drop-reason-desc); pick from the list', options?.dropReasons, true)}
            <label className="block min-w-0" title="Hubble event type (--type); only policy-verdict events say which policy decided">
              <span className="mb-1 block text-[0.6rem] font-semibold tracking-[0.1em] text-ink-dim uppercase">Event type</span>
              <select
                value={filter.type}
                onChange={(e) => onChange({ ...filter, type: e.target.value })}
                className={inputClass(filter.type !== '')}
              >
                <option value="">Any</option>
                {(options?.eventTypes ?? ['policy-verdict']).map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
        {row(
          'Either side',
          input('pod', 'Pod', 'ns/api-', 'This pod as the source OR the destination (--pod)')
        )}
        {row(
          'From',
          <>
            {input('fromPod', 'Pod', 'ns/web-', 'Source pod name prefix (--from-pod)')}
            {input('fromLabel', 'Label / entity', 'reserved:world', 'Source label or entity (--from-label), e.g. k8s:app=web, reserved:world')}
            {input('fromIp', 'IP / CIDR', '203.0.113.0/24', 'Source IP or CIDR (--from-ip)')}
          </>
        )}
        {row(
          'To',
          <>
            {input('toPod', 'Pod', 'ns/db-', 'Destination pod name prefix (--to-pod)')}
            {input('toService', 'Service', 'ns/db', 'Destination Service (--to-service)')}
            {input('toLabel', 'Label / entity', 'k8s:app=db', 'Destination label or entity (--to-label), e.g. reserved:kube-apiserver')}
            {input('toIp', 'IP / CIDR', '10.0.0.0/8', 'Destination IP or CIDR (--to-ip)')}
            {input('toPort', 'Port', '443', 'Destination port (--to-port)')}
          </>
        )}
        {row(
          'L7',
          <>
            {input('httpMethod', 'HTTP method', 'GET', 'HTTP request method (--http-method)', ['GET', 'POST', 'PUT', 'DELETE'])}
            {input('httpPath', 'HTTP path', '/api/.*', 'HTTP path, a regex (--http-path)')}
            {input('httpStatus', 'HTTP status', '5+', 'HTTP response status, or a class like 4+ (--http-status)', ['403', '4+', '5+'])}
            {input('toFqdn', 'To FQDN', 'api.github.com', "Destination DNS name, as Cilium's DNS proxy learned it (--to-fqdn)")}
          </>
        )}

        <p className="text-[0.7rem] leading-relaxed text-ink-faint">
          {intro} Hubble applies filters before sampling, so all <em>Last</em> flows match. Fields combine with AND;
          commas separate alternatives. Same as the CLI's <code className="text-ink-dim">--pod</code>,{' '}
          <code className="text-ink-dim">--from-*</code>, <code className="text-ink-dim">--to-*</code>,{' '}
          <code className="text-ink-dim">--verdict</code>, <code className="text-ink-dim">--drop-reason-desc</code>,{' '}
          <code className="text-ink-dim">--type</code>, <code className="text-ink-dim">--http-*</code> and{' '}
          <code className="text-ink-dim">--to-fqdn</code>. L7 fields only match traffic already behind Cilium's proxy.
        </p>
      </div>
    </details>
  )
}
