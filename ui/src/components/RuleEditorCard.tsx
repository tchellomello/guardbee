// Editor for a single ingress/egress rule — peer labels (manual or picked
// live from the cluster), entities, CIDRs, and ports. Used inside the
// Policy Topology Map's detail panel when a rule node is selected, so the
// graph itself is the editor rather than a separate flat form.

import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { fetchFlows, type Flow, type Pod } from '../api'
import {
  groupPodsBySignature,
  nonVolatileLabels,
  parseNamespacePod,
  podMatchesSelector,
  primaryLabel,
  useNamespacePods,
  workloadSignature,
} from '../shared/podLabels'
import { useAnchoredPosition } from '../shared/useAnchoredPosition'
import type { EgressRule, EndpointSelectorRule, IngressRule, Protocol } from '../policy'

export function RuleEditorCard({
  ruleNumber,
  type,
  rule,
  targetNamespace,
  targetLabels,
  availableNamespaces,
  onUpdate,
  onRemove,
}: {
  ruleNumber: number
  type: 'ingress' | 'egress'
  rule: IngressRule | EgressRule
  targetNamespace: string
  targetLabels: Record<string, string>
  availableNamespaces: string[]
  onUpdate: (updated: IngressRule | EgressRule) => void
  onRemove: () => void
}) {
  const isIngress = type === 'ingress'
  const endpoints = isIngress
    ? (rule as IngressRule).fromEndpoints
    : (rule as EgressRule).toEndpoints

  function handleAddEndpoint() {
    const nextEndpoints = [...endpoints, { matchLabels: { app: '' } }]
    onUpdate(
      isIngress
        ? { ...rule, fromEndpoints: nextEndpoints }
        : { ...rule, toEndpoints: nextEndpoints }
    )
  }

  function handleUpdateEndpoint(idx: number, key: string, value: string, ns?: string) {
    const next = endpoints.map((ep, i) => {
      if (i !== idx) return ep
      return {
        matchLabels: key ? { [key]: value } : {},
        namespace: ns !== undefined ? ns : ep.namespace,
      }
    })
    onUpdate(isIngress ? { ...rule, fromEndpoints: next } : { ...rule, toEndpoints: next })
  }

  function handleRemoveEndpoint(idx: number) {
    const next = endpoints.filter((_, i) => i !== idx)
    onUpdate(isIngress ? { ...rule, fromEndpoints: next } : { ...rule, toEndpoints: next })
  }

  function handleAddLabelPeer(ns: string, key: string, value: string) {
    const next = [...endpoints, { matchLabels: { [key]: value }, namespace: ns || undefined }]
    onUpdate(isIngress ? { ...rule, fromEndpoints: next } : { ...rule, toEndpoints: next })
  }

  // Ports
  function handleAddPort() {
    const nextPorts = [...rule.toPorts, { port: '80', protocol: 'TCP' as Protocol }]
    onUpdate({ ...rule, toPorts: nextPorts })
  }

  function handleUpdatePort(idx: number, port: string, protocol: Protocol) {
    const nextPorts = rule.toPorts.map((p, i) => (i === idx ? { port, protocol } : p))
    onUpdate({ ...rule, toPorts: nextPorts })
  }

  function handleRemovePort(idx: number) {
    const nextPorts = rule.toPorts.filter((_, i) => i !== idx)
    onUpdate({ ...rule, toPorts: nextPorts })
  }

  // Entities
  const entities = isIngress
    ? (rule as IngressRule).fromEntities
    : (rule as EgressRule).toEntities

  function toggleEntity(ent: string) {
    const next = entities.includes(ent)
      ? entities.filter((e) => e !== ent)
      : [...entities, ent]
    onUpdate(isIngress ? { ...rule, fromEntities: next } : { ...rule, toEntities: next })
  }

  function handleAddEntity(ent: string) {
    if (entities.includes(ent)) return
    const next = [...entities, ent]
    onUpdate(isIngress ? { ...rule, fromEntities: next } : { ...rule, toEntities: next })
  }

  // CIDRs
  const cidrs = isIngress ? (rule as IngressRule).fromCIDRs : (rule as EgressRule).toCIDRs

  function handleCIDRChange(val: string) {
    const parts = val.split(',').map((s) => s.trim()).filter(Boolean)
    onUpdate(isIngress ? { ...rule, fromCIDRs: parts } : { ...rule, toCIDRs: parts })
  }

  function handleAddCIDR(cidr: string) {
    if (cidrs.includes(cidr)) return
    const next = [...cidrs, cidr]
    onUpdate(isIngress ? { ...rule, fromCIDRs: next } : { ...rule, toCIDRs: next })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between border-b border-line pb-2">
        <span className="font-display text-[0.7rem] font-bold uppercase tracking-wider text-ink">
          {isIngress ? `From Ingress Source #${ruleNumber}` : `To Egress Destination #${ruleNumber}`}
        </span>
        <button
          type="button"
          onClick={onRemove}
          className="text-xs text-ink-dim hover:text-drop cursor-pointer"
          title="Remove rule"
        >
          ✕ Remove Rule
        </button>
      </div>

      {/* Peer Endpoints */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
            {'{}'} Workload Peer Labels ({isIngress ? 'fromEndpoints' : 'toEndpoints'})
          </label>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleAddEndpoint}
              className="text-[0.65rem] text-signal hover:underline cursor-pointer"
            >
              + Blank Peer
            </button>
            <AddPeerMenu
              isIngress={isIngress}
              targetNamespace={targetNamespace}
              targetLabels={targetLabels}
              availableNamespaces={availableNamespaces}
              onAddLabelPeer={handleAddLabelPeer}
              onAddEntity={handleAddEntity}
              onAddCIDR={handleAddCIDR}
            />
          </div>
        </div>

        {endpoints.map((ep, idx) => {
          const [labelKey = '', labelVal = ''] = Object.entries(ep.matchLabels)[0] || []
          return (
            <div key={idx} className="flex flex-wrap items-center gap-2">
              <input
                type="text"
                value={labelKey}
                placeholder="label (app)"
                onChange={(e) => handleUpdateEndpoint(idx, e.target.value, labelVal)}
                className="w-28 border border-line bg-void px-2 py-1 text-xs text-ink font-mono focus:border-signal focus:outline-none"
              />
              <span className="text-ink-dim font-bold">=</span>
              <input
                type="text"
                value={labelVal}
                placeholder="value (frontend)"
                onChange={(e) => handleUpdateEndpoint(idx, labelKey, e.target.value)}
                className="w-32 border border-line bg-void px-2 py-1 text-xs text-ink font-mono focus:border-signal focus:outline-none"
              />
              <input
                type="text"
                list="rule-editor-peer-namespaces"
                value={ep.namespace || ''}
                placeholder="namespace (optional)"
                onChange={(e) => handleUpdateEndpoint(idx, labelKey, labelVal, e.target.value)}
                className="w-36 border border-line bg-void px-2 py-1 text-xs text-ink font-mono focus:border-signal focus:outline-none"
              />
              <button
                type="button"
                onClick={() => handleRemoveEndpoint(idx)}
                className="text-xs text-ink-dim hover:text-drop cursor-pointer"
              >
                ✕
              </button>
            </div>
          )
        })}
        <datalist id="rule-editor-peer-namespaces">
          {availableNamespaces.map((ns) => (
            <option key={ns} value={ns} />
          ))}
        </datalist>
      </div>

      <MatchingPodsPreview endpoints={endpoints} fallbackNamespace={targetNamespace} />

      {/* Entities & CIDRs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-line/60">
        <div>
          <label className="block mb-1.5 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
            ⎈ Entities ({isIngress ? 'fromEntities' : 'toEntities'})
          </label>
          <div className="flex flex-wrap gap-2 text-xs">
            {['world', 'cluster', 'host'].map((ent) => (
              <label
                key={ent}
                className={`flex items-center gap-1.5 border px-2 py-1 cursor-pointer transition-colors ${
                  entities.includes(ent)
                    ? 'border-signal bg-signal/10 text-signal font-semibold'
                    : 'border-line bg-void text-ink-dim hover:text-ink'
                }`}
              >
                <input
                  type="checkbox"
                  checked={entities.includes(ent)}
                  onChange={() => toggleEntity(ent)}
                  className="peer sr-only"
                />
                {/* peer-focus-visible (not :focus) so the ring only shows for
                    keyboard navigation — same sr-only-checkbox pattern as
                    NamespaceScope's CheckRow. */}
                <span className="peer-focus-visible:ring-2 peer-focus-visible:ring-signal peer-focus-visible:ring-offset-1 peer-focus-visible:ring-offset-void">
                  {ent}
                </span>
              </label>
            ))}
          </div>
        </div>

        <div>
          <label className="block mb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
            🌐 CIDR Subnets ({isIngress ? 'fromCIDR' : 'toCIDR'})
          </label>
          <input
            type="text"
            value={cidrs.join(', ')}
            placeholder="10.0.0.0/8, 192.168.1.0/24"
            onChange={(e) => handleCIDRChange(e.target.value)}
            className="w-full border border-line bg-void px-2.5 py-1 text-xs text-ink font-mono focus:border-signal focus:outline-none"
          />
        </div>
      </div>

      {/* Allowed Ports */}
      <div className="pt-2 border-t border-line/60 space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
            Allowed Ports & Protocols (toPorts)
          </label>
          <button
            type="button"
            onClick={handleAddPort}
            className="text-[0.65rem] text-signal hover:underline cursor-pointer"
          >
            + Add Port
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {rule.toPorts.map((p, idx) => (
            <div key={idx} className="flex items-center gap-1 border border-line bg-void px-2 py-1 text-xs">
              <input
                type="text"
                value={p.port}
                placeholder="port (80)"
                onChange={(e) => handleUpdatePort(idx, e.target.value, p.protocol)}
                className="w-16 border border-transparent bg-transparent font-mono text-ink focus:border-signal focus:outline-none"
              />
              <select
                value={p.protocol}
                onChange={(e) => handleUpdatePort(idx, p.port, e.target.value as Protocol)}
                className="bg-panel border-l border-line pl-1 font-mono text-ink text-[11px] focus:outline-none cursor-pointer"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="ANY">ANY</option>
              </select>
              <button
                type="button"
                onClick={() => handleRemovePort(idx)}
                className="ml-1 text-ink-dim hover:text-drop cursor-pointer"
              >
                ✕
              </button>
            </div>
          ))}
          {rule.toPorts.length === 0 && (
            <span className="text-xs text-ink-faint italic">Any port / protocol allowed</span>
          )}
        </div>
      </div>
    </div>
  )
}

// Shows which real cluster pods a peer's saved matchLabels would actually
// select right now — ground truth after the fact, complementing the
// AddPeerMenu wizard's ground truth before the fact.
function MatchingPodsPreview({
  endpoints,
  fallbackNamespace,
}: {
  endpoints: EndpointSelectorRule[]
  fallbackNamespace: string
}) {
  const namespaces = useMemo(
    () =>
      Array.from(
        new Set(endpoints.map((ep) => ep.namespace || fallbackNamespace).filter(Boolean))
      ),
    [endpoints, fallbackNamespace]
  )
  const { byNamespace, loading } = useNamespacePods(namespaces)

  const withLabels = endpoints.filter((ep) => Object.keys(ep.matchLabels).some((k) => k.trim()))
  if (withLabels.length === 0) return null

  return (
    <div className="space-y-2 border-t border-line/60 pt-2">
      <label className="text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
        Matching Pods (live)
      </label>
      {withLabels.map((ep, idx) => {
        const ns = ep.namespace || fallbackNamespace
        const pods = ns ? byNamespace[ns] : undefined
        const matched = pods?.filter((p) => podMatchesSelector(p.labels, ep.matchLabels)) ?? []
        const labelText = Object.entries(ep.matchLabels).map(([k, v]) => `${k}=${v}`).join(', ')

        return (
          <div key={idx} className="border border-line bg-void px-2.5 py-1.5">
            <div className="text-[0.65rem] text-ink-dim">
              <span className="font-mono text-ink">{labelText}</span>
              {ns && <> in <span className="text-ink">{ns}</span></>}
            </div>
            {!ns && <p className="mt-1 text-xs text-ink-faint italic">No namespace set — cannot look up live pods.</p>}
            {ns && loading && pods === undefined && (
              <p className="mt-1 text-xs text-ink-dim">Looking up pods in {ns}…</p>
            )}
            {ns && pods !== undefined && matched.length === 0 && (
              <p className="mt-1 text-xs text-ink-faint italic">No running pods in {ns} currently match this selector.</p>
            )}
            {matched.length > 0 && (
              <div className="mt-1.5 space-y-1">
                {matched.map((pod) => (
                  <div key={pod.name}>
                    <div className="font-mono text-[0.7rem] text-ink">{pod.name}</div>
                    <div className="mt-0.5 flex flex-wrap gap-1">
                      {nonVolatileLabels(pod.labels).map(([k, v]) => (
                        <span
                          key={k}
                          className="border border-signal/30 bg-signal/5 px-1.5 py-0.5 text-[0.6rem] font-mono text-signal"
                        >
                          {k}={v}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// Boxy "+ Add Rule" split control: a blank rule, or one of a handful of
// common ready-made rules (DNS, world HTTPS, cluster-internal, …) dropped
// in with one click instead of hand-building the same shape every time.
export function AddRuleMenu<T extends { id: string; name: string; description: string }>({
  label,
  presets,
  onAddBlank,
  onAddPreset,
}: {
  label: string
  presets: T[]
  onAddBlank: () => void
  onAddPreset: (preset: T) => void
}) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const pos = useAnchoredPosition(triggerRef, open)

  return (
    <div className="relative flex">
      <button
        type="button"
        onClick={onAddBlank}
        className="border border-signal bg-signal/10 px-2.5 py-1 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal hover:text-void transition-colors cursor-pointer"
      >
        + {label}
      </button>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Add from a preset rule"
        className="border border-l-0 border-signal bg-signal/10 px-1.5 py-1 text-[0.65rem] font-bold text-signal hover:bg-signal hover:text-void transition-colors cursor-pointer"
      >
        ▾
      </button>
      {open && pos && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div
            // maxHeight clamped to the remaining viewport below the trigger
            // (with a small bottom margin) + overflow-y-auto: this list grew
            // past a handful of presets (9 ingress / 11 egress as of this
            // writing) and a fixed-position panel with no height limit just
            // ran off the bottom of the viewport with no way to reach the
            // rest — confirmed by a real screenshot where the last few
            // presets were cut off mid-description.
            className="fixed z-30 flex w-80 flex-col overflow-y-auto border border-line-bright bg-panel-raised shadow-lg"
            style={{ top: pos.top, right: pos.right, maxHeight: `calc(100vh - ${pos.top}px - 16px)` }}
          >
            <div className="sticky top-0 z-10 border-b border-line bg-panel-raised px-3 py-1.5 text-[0.6rem] font-bold uppercase tracking-wider text-ink-dim">
              Preset Rules
            </div>
            {presets.map((preset) => (
              <button
                key={preset.id}
                type="button"
                onClick={() => {
                  onAddPreset(preset)
                  setOpen(false)
                }}
                className="block w-full border-b border-line px-3 py-2 text-left last:border-b-0 hover:bg-signal/10 cursor-pointer"
              >
                <div className="text-xs font-semibold text-ink">{preset.name}</div>
                <div className="mt-0.5 text-[0.65rem] text-ink-dim leading-snug">{preset.description}</div>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

export interface TrafficPeerPick {
  peer: string
  count: number
  kind: 'pod' | 'entity' | 'cidr' | 'unsupported'
  label?: [string, string]
  entity?: string
  cidr?: string
}

// Classifies a flow's raw endpoint string (see the backend's endpointString
// in flows.go) into the kind of rule peer it would become if added: a real
// pod becomes a label peer (via its live, non-volatile labels), a
// world/host reserved identity becomes an entity, a bare IP becomes a /32
// CIDR, and anything else (other reserved identities, unresolvable
// identities) is shown but not pickable yet — the form doesn't have a slot
// for it.
export function classifyTrafficPeer(peer: string, peerPodsByNs: Record<string, Pod[]>): Omit<TrafficPeerPick, 'count'> {
  const parsed = parseNamespacePod(peer)
  if (parsed) {
    const pod = peerPodsByNs[parsed.namespace]?.find((p) => p.name === parsed.podName)
    const label = pod ? primaryLabel(workloadSignature(pod.labels)) : null
    return label ? { peer, kind: 'pod', label } : { peer, kind: 'unsupported' }
  }
  if (peer === 'reserved:world') return { peer, kind: 'entity', entity: 'world' }
  if (peer === 'reserved:host') return { peer, kind: 'entity', entity: 'host' }
  if (peer.startsWith('reserved:')) return { peer, kind: 'unsupported' }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(peer)) return { peer, kind: 'cidr', cidr: `${peer}/32` }
  return { peer, kind: 'unsupported' }
}

// Dropdown that adds a fully-formed rule peer (label selector, entity, or
// CIDR) directly from live cluster state instead of typing it in blind.
// "Running Pods" lists distinct workloads (deduped by non-volatile label
// signature) in a chosen namespace. "Observed Traffic" samples real recent
// flows touching the policy's own target workload and surfaces the actual
// peers seen — pods, world/host, or external IPs — so a rule can be built
// from what's really happening on the wire, not guesswork.
function AddPeerMenu({
  isIngress,
  targetNamespace,
  targetLabels,
  availableNamespaces,
  onAddLabelPeer,
  onAddEntity,
  onAddCIDR,
}: {
  isIngress: boolean
  targetNamespace: string
  targetLabels: Record<string, string>
  availableNamespaces: string[]
  onAddLabelPeer: (namespace: string, key: string, value: string) => void
  onAddEntity: (entity: string) => void
  onAddCIDR: (cidr: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'pods' | 'traffic'>('pods')
  const [podNamespace, setPodNamespace] = useState(targetNamespace)
  const namespaceListId = useId()

  useEffect(() => {
    if (!podNamespace && targetNamespace) setPodNamespace(targetNamespace)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetNamespace])

  const { byNamespace: podsByNs, loading: podsLoading } = useNamespacePods(
    open && tab === 'pods' && podNamespace ? [podNamespace] : []
  )
  const podGroups = useMemo(() => groupPodsBySignature(podsByNs[podNamespace] ?? []), [podsByNs, podNamespace])

  const [flows, setFlows] = useState<Flow[] | null>(null)
  const [flowsLoading, setFlowsLoading] = useState(false)
  const [flowsError, setFlowsError] = useState<string | null>(null)

  useEffect(() => {
    setFlows(null)
    setFlowsError(null)
  }, [targetNamespace])

  useEffect(() => {
    if (!open || tab !== 'traffic' || !targetNamespace || flows !== null || flowsLoading) return
    setFlowsLoading(true)
    setFlowsError(null)
    fetchFlows(targetNamespace, 300)
      .then((res) => setFlows(res.flows))
      .catch((err) => setFlowsError(err instanceof Error ? err.message : String(err)))
      .finally(() => setFlowsLoading(false))
  }, [open, tab, targetNamespace, flows, flowsLoading])

  const { byNamespace: targetNsPods, loading: targetPodsLoading } = useNamespacePods(
    open && tab === 'traffic' && targetNamespace ? [targetNamespace] : []
  )

  // How many live pods in the target namespace actually match the target's
  // current labels — distinguishes "nothing to sample against yet because
  // the target isn't set to anything real" from "the target's real, it's
  // just quiet in this 300-flow sample" so the empty state doesn't read as
  // broken either way.
  const matchedTargetPodCount = useMemo(() => {
    const targetPods = targetNsPods[targetNamespace] ?? []
    return targetPods.filter((p) => podMatchesSelector(p.labels, targetLabels)).length
  }, [targetNsPods, targetNamespace, targetLabels])

  // Flows where the target workload's own pod is on the relevant side
  // (destination for ingress, source for egress), counted by distinct peer.
  const trafficCounts = useMemo(() => {
    if (!flows) return []
    const targetPods = targetNsPods[targetNamespace] ?? []
    const matchedNames = new Set(
      targetPods.filter((p) => podMatchesSelector(p.labels, targetLabels)).map((p) => p.name)
    )
    if (matchedNames.size === 0) return []
    const counts = new Map<string, number>()
    for (const f of flows) {
      const self = isIngress ? f.destination : f.source
      const parsedSelf = parseNamespacePod(self)
      if (!parsedSelf || !matchedNames.has(parsedSelf.podName)) continue
      const peer = isIngress ? f.source : f.destination
      counts.set(peer, (counts.get(peer) ?? 0) + 1)
    }
    return Array.from(counts.entries())
      .map(([peer, count]) => ({ peer, count }))
      .sort((a, b) => b.count - a.count)
  }, [flows, targetNsPods, targetNamespace, targetLabels, isIngress])

  const peerNamespaces = useMemo(
    () =>
      Array.from(
        new Set(
          trafficCounts
            .map(({ peer }) => parseNamespacePod(peer)?.namespace)
            .filter((ns): ns is string => !!ns)
        )
      ),
    [trafficCounts]
  )
  const { byNamespace: peerPodsByNs } = useNamespacePods(open && tab === 'traffic' ? peerNamespaces : [])

  // Classify each distinct peer, then merge entries that would produce the
  // same rule peer (e.g. several DaemonSet replica pods sharing one label)
  // so the list shows one pickable row per distinct rule outcome instead of
  // one per pod.
  const trafficPicks: TrafficPeerPick[] = useMemo(() => {
    const merged = new Map<string, TrafficPeerPick>()
    for (const { peer, count } of trafficCounts) {
      const classified = classifyTrafficPeer(peer, peerPodsByNs)
      const dedupeKey =
        classified.kind === 'pod' && classified.label
          ? `pod:${classified.label[0]}=${classified.label[1]}`
          : classified.kind === 'entity'
          ? `entity:${classified.entity}`
          : classified.kind === 'cidr'
          ? `cidr:${classified.cidr}`
          : `unsupported:${peer}`
      const existing = merged.get(dedupeKey)
      if (existing) {
        existing.count += count
      } else {
        merged.set(dedupeKey, { ...classified, count })
      }
    }
    return Array.from(merged.values()).sort((a, b) => b.count - a.count)
  }, [trafficCounts, peerPodsByNs])

  function pickTraffic(p: TrafficPeerPick) {
    if (p.kind === 'pod' && p.label) {
      onAddLabelPeer(parseNamespacePod(p.peer)!.namespace, p.label[0], p.label[1])
    } else if (p.kind === 'entity' && p.entity) {
      onAddEntity(p.entity)
    } else if (p.kind === 'cidr' && p.cidr) {
      onAddCIDR(p.cidr)
    } else {
      return
    }
    setOpen(false)
  }

  const triggerRef = useRef<HTMLButtonElement>(null)
  const pos = useAnchoredPosition(triggerRef, open)

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        title="Pick a peer from live cluster pods or observed traffic"
        className="border border-line bg-void/60 px-2 py-1 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:border-signal cursor-pointer"
      >
        ⌖ Pick Entities ▾
      </button>
      {open && pos && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div
            className="fixed z-30 w-80 border border-line-bright bg-panel-raised shadow-lg"
            style={{ top: pos.top, left: Math.min(pos.left, window.innerWidth - 328) }}
          >
            <div className="flex border-b border-line">
              <button
                type="button"
                onClick={() => setTab('pods')}
                className={`flex-1 px-3 py-1.5 text-[0.65rem] font-bold uppercase tracking-wider cursor-pointer ${
                  tab === 'pods' ? 'bg-signal/10 text-signal' : 'text-ink-dim hover:text-ink'
                }`}
              >
                Running Pods
              </button>
              <button
                type="button"
                onClick={() => setTab('traffic')}
                className={`flex-1 border-l border-line px-3 py-1.5 text-[0.65rem] font-bold uppercase tracking-wider cursor-pointer ${
                  tab === 'traffic' ? 'bg-signal/10 text-signal' : 'text-ink-dim hover:text-ink'
                }`}
              >
                Observed Traffic
              </button>
            </div>

            {tab === 'pods' && (
              <div className="max-h-72 overflow-y-auto">
                <div className="border-b border-line px-3 py-1.5">
                  <input
                    type="text"
                    list={namespaceListId}
                    value={podNamespace}
                    onChange={(e) => setPodNamespace(e.target.value)}
                    placeholder="namespace"
                    className="w-full border border-line bg-void px-2 py-1 text-xs text-ink font-mono focus:border-signal focus:outline-none"
                  />
                  <datalist id={namespaceListId}>
                    {availableNamespaces.map((ns) => (
                      <option key={ns} value={ns} />
                    ))}
                  </datalist>
                </div>
                {!podNamespace && (
                  <div className="px-3 py-2 text-xs text-ink-faint italic">Set a namespace to list its pods.</div>
                )}
                {podNamespace && podsLoading && podGroups.length === 0 && (
                  <div className="px-3 py-2 text-xs text-ink-dim">Loading pods in {podNamespace}…</div>
                )}
                {podNamespace && !podsLoading && podGroups.length === 0 && (
                  <div className="px-3 py-2 text-xs text-ink-faint italic">
                    No labeled pods found in {podNamespace}
                  </div>
                )}
                {podGroups.map((g) => {
                  const primary = primaryLabel(g.signature)
                  if (!primary) return null
                  const [key, value] = primary
                  return (
                    <button
                      key={JSON.stringify(g.signature)}
                      type="button"
                      onClick={() => {
                        onAddLabelPeer(podNamespace, key, value)
                        setOpen(false)
                      }}
                      className="flex w-full items-center justify-between gap-2 border-b border-line px-3 py-2 text-left last:border-b-0 hover:bg-signal/10 cursor-pointer"
                    >
                      <span className="truncate font-mono text-xs text-ink">
                        {key}={value}
                      </span>
                      <span className="shrink-0 text-[0.6rem] text-ink-faint">
                        {g.count} pod{g.count === 1 ? '' : 's'}
                      </span>
                    </button>
                  )
                })}
              </div>
            )}

            {tab === 'traffic' && (
              <div className="max-h-72 overflow-y-auto">
                {!targetNamespace && (
                  <div className="px-3 py-2 text-xs text-ink-faint italic">
                    Set the policy's target namespace first.
                  </div>
                )}
                {targetNamespace && flowsLoading && (
                  <div className="px-3 py-2 text-xs text-ink-dim">Sampling live traffic in {targetNamespace}…</div>
                )}
                {flowsError && <div className="px-3 py-2 text-xs text-drop">{flowsError}</div>}
                {targetNamespace &&
                  !flowsLoading &&
                  !flowsError &&
                  flows !== null &&
                  trafficPicks.length === 0 &&
                  (targetPodsLoading ? (
                    <div className="px-3 py-2 text-xs text-ink-dim">Checking which pods match the target…</div>
                  ) : matchedTargetPodCount === 0 ? (
                    <div className="px-3 py-2 text-xs text-ink-faint italic">
                      No running pods in {targetNamespace} currently match the target's labels — pick a real
                      target first (Target Workload node, or the "Running Pods" tab here) before traffic can be
                      attributed to it.
                    </div>
                  ) : (
                    <div className="px-3 py-2 text-xs text-ink-faint italic">
                      Target matches {matchedTargetPodCount} running pod{matchedTargetPodCount === 1 ? '' : 's'},
                      but no recent {isIngress ? 'inbound' : 'outbound'} flows touched{' '}
                      {matchedTargetPodCount === 1 ? 'it' : 'them'} in this 300-flow sample — try again after more
                      traffic, or use Follow mode on the Flows tab for denser coverage.
                    </div>
                  ))}
                {trafficPicks.map((p) => {
                  const disabled = p.kind === 'unsupported'
                  const display =
                    p.kind === 'entity'
                      ? `entity: ${p.entity}`
                      : p.kind === 'cidr'
                      ? `CIDR: ${p.cidr}`
                      : p.kind === 'pod' && p.label
                      ? `${p.label[0]}=${p.label[1]}`
                      : p.peer
                  return (
                    <button
                      key={p.peer}
                      type="button"
                      disabled={disabled}
                      onClick={() => pickTraffic(p)}
                      title={disabled ? `${p.peer} isn't representable as a rule peer yet` : p.peer}
                      className="flex w-full items-center justify-between gap-2 border-b border-line px-3 py-2 text-left last:border-b-0 hover:bg-signal/10 cursor-pointer disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent"
                    >
                      <span className="truncate font-mono text-xs text-ink">{display}</span>
                      <span className="shrink-0 text-[0.6rem] text-ink-faint">{p.count}×</span>
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
