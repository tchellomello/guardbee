// 3-column visual topology graph for CiliumNetworkPolicy authoring:
// [ Ingress Sources ] ---> [ Target Workload ] ---> [ Egress Destinations ]
//
// The graph IS the editor, not just a visualization of it: click the
// target node to edit its endpointSelector (with a live cluster-pod
// picker), click a rule node to edit its peers/entities/CIDRs/ports in
// place, click the dashed "+" node at the bottom of a column to add a new
// rule (blank or from a preset).

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  getBezierPath,
  Position,
  ReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeChange,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { AddRuleMenu, RuleEditorCard } from './RuleEditorCard'
import { groupPodsBySignature, useNamespacePods } from '../shared/podLabels'
import { useAnchoredPosition } from '../shared/useAnchoredPosition'
import {
  ruleHasNoEffectiveSelector,
  ruleProducesNoOutput,
  type EgressRule,
  type EgressRulePreset,
  type IngressRule,
  type IngressRulePreset,
  type PolicyModel,
} from '../policy'
import { useTheme } from '../theme'

// Raw (non-JSX) description of a node, carried alongside its rendered label
// so the selected-node detail panel can show un-truncated fields and cross-
// reference them against live cluster pods — the node box itself only has
// room for a `line-clamp-2` summary.
interface NodePeer {
  labels: Record<string, string>
  namespace?: string
}

interface NodeDetail {
  title: string
  kind: 'target' | 'ingress' | 'egress' | 'ingress-add' | 'egress-add'
  namespace?: string
  peers?: NodePeer[]
  cidrs?: string[]
  entities?: string[]
  ports?: { port: string; protocol: string }[]
  rule?: IngressRule | EgressRule
}

const BASE_NODE_CLASS =
  '!w-[240px] !whitespace-normal !break-words !rounded-none !border !px-3 !py-2.5 !text-xs !font-mono cursor-pointer transition-all duration-200 select-none'

const ROW_HEIGHT = 130
const NODE_WIDTH = 240
const COLUMN_GAP = 40
// Floor for the width used in column math, not a floor on the real
// container — it's just enough for three 240px node boxes with a 40px gap
// between each so they never visually overlap. A narrow real container
// still overflows this (same as the old fixed 1320px-wide layout did), and
// fitView's zoom-out is what makes that legible, not squeezing the columns
// together.
const MIN_LAYOUT_WIDTH = 3 * NODE_WIDTH + 2 * COLUMN_GAP

// Column anchor X positions as a function of the actual rendered container
// width, rather than fixed pixel constants — fixed constants left large
// dead margins on a wide viewport (fitView fitting a ~1320px-wide layout
// into a much wider container) and pushed the Target/Egress columns
// off-canvas on a narrow one (minZoom couldn't zoom out far enough to fit
// 1320px into ~390px). Scaling the anchors to the container means the
// layout always spans close to the full width, so fitView fills the
// available space at any viewport size.
function computeColumnX(width: number) {
  const w = Math.max(width, MIN_LAYOUT_WIDTH)
  return {
    ingress: 0,
    target: w / 2 - NODE_WIDTH / 2,
    egress: w - NODE_WIDTH,
  }
}

interface PolicyEdgeData {
  label: string
  color: string
  isDimmed: boolean
  direction: 'ingress' | 'egress'
  [key: string]: unknown
}

type CustomEdge = Edge<PolicyEdgeData, 'policyEdge'>

function PolicyEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition = Position.Right,
  targetPosition = Position.Left,
  style = {},
  data,
}: EdgeProps<CustomEdge>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const isDimmed = data?.isDimmed ?? false
  const color = data?.color ?? '#22e9c7'

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          ...style,
          stroke: color,
          strokeWidth: isDimmed ? 1 : 2,
          opacity: isDimmed ? 0.1 : 1,
          transition: 'opacity 0.2s ease, stroke-width 0.2s ease',
        }}
      />
      {data?.label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: isDimmed ? 'none' : 'all',
              opacity: isDimmed ? 0.05 : 1,
              transition: 'opacity 0.2s ease',
            }}
            className="z-10 flex items-center gap-1 rounded-sm border border-signal/40 bg-panel px-2 py-0.5 font-mono text-[11px] font-semibold tracking-tight text-signal shadow-xs select-none backdrop-blur-xs"
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

const edgeTypes = {
  policyEdge: PolicyEdgeComponent,
}

interface PolicyGraphProps {
  policy: PolicyModel
  availableNamespaces: string[]
  ingressPresets: IngressRulePreset[]
  egressPresets: EgressRulePreset[]
  // Set by a parent that just added a rule on this policy's behalf (e.g.
  // "Add to Policy" from a Verdict row) — selects and opens that rule's
  // node for editing, then is consumed/cleared via onConsumeAutoSelect so
  // it doesn't re-trigger on every re-render.
  autoSelectNodeId?: string | null
  onConsumeAutoSelect?: () => void
  onUpdateTargetLabels: (labels: Record<string, string>) => void
  onAddIngressRule: (rule?: IngressRule) => string
  onUpdateIngressRule: (id: string, updated: IngressRule) => void
  onRemoveIngressRule: (id: string) => void
  onAddEgressRule: (rule?: EgressRule) => string
  onUpdateEgressRule: (id: string, updated: EgressRule) => void
  onRemoveEgressRule: (id: string) => void
}

export function PolicyGraph({
  policy,
  availableNamespaces,
  ingressPresets,
  egressPresets,
  autoSelectNodeId,
  onConsumeAutoSelect,
  onUpdateTargetLabels,
  onAddIngressRule,
  onUpdateIngressRule,
  onRemoveIngressRule,
  onAddEgressRule,
  onUpdateEgressRule,
  onRemoveEgressRule,
}: PolicyGraphProps) {
  const { theme } = useTheme()
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)

  useEffect(() => {
    if (!autoSelectNodeId) return
    setSelectedNodeId(autoSelectNodeId)
    onConsumeAutoSelect?.()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoSelectNodeId])

  function handleAddIngress(rule?: IngressRule) {
    const id = onAddIngressRule(rule)
    setSelectedNodeId(`ingress-${id}`)
  }

  function handleAddEgress(rule?: EgressRule) {
    const id = onAddEgressRule(rule)
    setSelectedNodeId(`egress-${id}`)
  }

  function handleRemoveIngress(id: string) {
    onRemoveIngressRule(id)
    setSelectedNodeId(null)
  }

  function handleRemoveEgress(id: string) {
    onRemoveEgressRule(id)
    setSelectedNodeId(null)
  }

  // User-dragged node positions, keyed by node id, layered on top of the
  // auto-layout buildGraph computes — so repositioning a box survives
  // buildGraph re-running on every policy edit (it recomputes fresh
  // positions each time, which would otherwise snap a dragged box right
  // back). Keyed by id rather than index so it still lines up after rules
  // are added/removed/reordered.
  const [dragPositions, setDragPositions] = useState<Record<string, { x: number; y: number }>>({})

  const handleNodesChange = useCallback((changes: NodeChange[]) => {
    const moved = changes.filter((c) => c.type === 'position' && c.position)
    if (moved.length === 0) return
    setDragPositions((prev) => {
      const next = { ...prev }
      for (const change of moved) {
        if (change.type === 'position' && change.position) {
          next[change.id] = change.position
        }
      }
      return next
    })
  }, [])

  // This graph always renders (there's no "empty, don't mount" guard), and
  // the Policy Editor tab stays mounted-but-hidden (display:none) when
  // another tab is active — so React Flow's one-time `fitView` on mount can
  // run against a collapsed 0-size container and never re-fit once the tab
  // is actually shown. Watch the container for a real resize (hidden→shown,
  // or an ordinary width change now that column anchors scale with it) and
  // re-fit then.
  const graphContainerRef = useRef<HTMLDivElement>(null)
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null)
  // Real container width, fed into buildGraph so the column anchors
  // (computeColumnX) track it instead of using fixed pixel constants.
  const [containerWidth, setContainerWidth] = useState(0)

  useEffect(() => {
    const el = graphContainerRef.current
    if (!el || !rfInstance) return
    let lastWidth = el.clientWidth
    const observer = new ResizeObserver(() => {
      const width = el.clientWidth
      if (lastWidth < 10 && width >= 10) {
        rfInstance.fitView({ padding: 0.2 })
      } else if (Math.abs(width - lastWidth) > 40) {
        // An ordinary resize, not just the hidden-tab 0→visible transition
        // above — re-fit so the now width-dependent column layout keeps
        // filling the container after a window resize instead of drifting
        // off-center.
        rfInstance.fitView({ padding: 0.2 })
      }
      lastWidth = width
      setContainerWidth(width)
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [rfInstance])

  const { initialNodes: laidOutNodes, initialEdges } = useMemo(
    () => buildGraph(policy, theme, containerWidth),
    [policy, theme, containerWidth]
  )

  const initialNodes = useMemo(
    () =>
      laidOutNodes.map((node) =>
        dragPositions[node.id] ? { ...node, position: dragPositions[node.id] } : node
      ),
    [laidOutNodes, dragPositions]
  )

  const { nodes, edges } = useMemo(() => {
    if (!selectedNodeId) {
      return { nodes: initialNodes, edges: initialEdges }
    }

    const connectedEdges = initialEdges.filter(
      (e) => e.source === selectedNodeId || e.target === selectedNodeId
    )
    const connectedEdgeIds = new Set(connectedEdges.map((e) => e.id))
    const connectedNodeIds = new Set<string>([selectedNodeId])
    for (const e of connectedEdges) {
      connectedNodeIds.add(e.source)
      connectedNodeIds.add(e.target)
    }

    const updatedNodes = initialNodes.map((node) => {
      const isSelected = node.id === selectedNodeId
      const isConnected = connectedNodeIds.has(node.id)

      let className = (node.data.baseClass as string) ?? BASE_NODE_CLASS
      if (isSelected) {
        className +=
          ' !border-signal !bg-[var(--color-panel-raised)] !text-[var(--color-ink)] ring-2 ring-signal shadow-[0_0_12px_var(--color-signal-glow)] z-20'
      } else if (isConnected) {
        className +=
          ' !border-[var(--color-line-bright)] !bg-[var(--color-panel-raised)] !text-[var(--color-ink)] shadow-[0_0_0_1px_var(--color-signal-glow)] z-10'
      } else {
        className +=
          ' !border-[var(--color-line)] !bg-[var(--color-panel)] !text-[var(--color-ink-faint)] opacity-20 filter grayscale'
      }

      return { ...node, className }
    })

    const updatedEdges = initialEdges.map((edge) => {
      const isConnected = connectedEdgeIds.has(edge.id)
      return {
        ...edge,
        data: {
          ...edge.data!,
          isDimmed: !isConnected,
        },
      }
    })

    return { nodes: updatedNodes, edges: updatedEdges }
  }, [initialNodes, initialEdges, selectedNodeId])

  const maxRows = Math.max(
    policy.ingressRules.length + 1,
    policy.egressRules.length + 1,
    2
  )
  const height = Math.max(480, Math.min(900, maxRows * ROW_HEIGHT + 140))

  const selectedDetail = initialNodes.find((n) => n.id === selectedNodeId)?.data.detail as
    | NodeDetail
    | undefined

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase">
        <div className="flex items-center gap-2 flex-1">
          <span className="h-px flex-1 bg-line" />
          <span>Policy Topology Map — click a node to edit it</span>
          <span className="h-px flex-1 bg-line" />
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2 px-3 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim border-b border-line bg-panel-raised/50">
        <div>1. Ingress Sources</div>
        <div className="text-center">2. Target Workload</div>
        <div className="text-right">3. Egress Destinations</div>
      </div>

      <div ref={graphContainerRef} className="border border-line bg-void relative" style={{ height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          edgeTypes={edgeTypes}
          onInit={setRfInstance}
          onNodesChange={handleNodesChange}
          onNodeClick={(_, node) => setSelectedNodeId((prev) => (prev === node.id ? null : node.id))}
          onPaneClick={() => setSelectedNodeId(null)}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          proOptions={{ hideAttribution: true }}
          colorMode={theme}
          minZoom={0.2}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={20}
            size={1}
            color={theme === 'dark' ? '#1c2b2c' : '#d0dddc'}
          />
          <Controls
            className="!border !border-[var(--color-line)] !bg-[var(--color-panel)] [&_button]:!border-[var(--color-line)] [&_button]:!bg-[var(--color-panel-raised)] [&_button]:!fill-[var(--color-ink)] [&_button:hover]:!bg-[var(--color-line)]"
            showInteractive={false}
          />
        </ReactFlow>
      </div>

      {selectedDetail && (
        <SelectedNodeEditorPanel
          detail={selectedDetail}
          policy={policy}
          availableNamespaces={availableNamespaces}
          ingressPresets={ingressPresets}
          egressPresets={egressPresets}
          onClose={() => setSelectedNodeId(null)}
          onUpdateTargetLabels={onUpdateTargetLabels}
          onAddIngress={handleAddIngress}
          onUpdateIngressRule={onUpdateIngressRule}
          onRemoveIngress={handleRemoveIngress}
          onAddEgress={handleAddEgress}
          onUpdateEgressRule={onUpdateEgressRule}
          onRemoveEgress={handleRemoveEgress}
        />
      )}
    </div>
  )
}

function SelectedNodeEditorPanel({
  detail,
  policy,
  availableNamespaces,
  ingressPresets,
  egressPresets,
  onClose,
  onUpdateTargetLabels,
  onAddIngress,
  onUpdateIngressRule,
  onRemoveIngress,
  onAddEgress,
  onUpdateEgressRule,
  onRemoveEgress,
}: {
  detail: NodeDetail
  policy: PolicyModel
  availableNamespaces: string[]
  ingressPresets: IngressRulePreset[]
  egressPresets: EgressRulePreset[]
  onClose: () => void
  onUpdateTargetLabels: (labels: Record<string, string>) => void
  onAddIngress: (rule?: IngressRule) => void
  onUpdateIngressRule: (id: string, updated: IngressRule) => void
  onRemoveIngress: (id: string) => void
  onAddEgress: (rule?: EgressRule) => void
  onUpdateEgressRule: (id: string, updated: EgressRule) => void
  onRemoveEgress: (id: string) => void
}) {
  // A modal rather than an inline panel below the (potentially long) graph —
  // so it's unmistakable that this node is the thing currently being
  // edited, without the user having to notice a panel appear far down the
  // page or scroll to find it.
  const panelRef = useRef<HTMLDivElement>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  // Captured once on mount (the element that had focus right before this
  // modal opened) so it can be restored on close instead of leaving focus
  // on whatever the modal's own markup happened to contain.
  const previouslyFocusedRef = useRef<Element | null>(null)

  useEffect(() => {
    previouslyFocusedRef.current = document.activeElement
    closeButtonRef.current?.focus()
    return () => {
      if (previouslyFocusedRef.current instanceof HTMLElement) {
        previouslyFocusedRef.current.focus()
      }
    }
  }, [])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key !== 'Tab') return
      // Manual focus trap: keep Tab/Shift+Tab cycling within the panel's
      // own focusable elements instead of escaping to the page behind it.
      const panel = panelRef.current
      if (!panel) return
      const focusable = panel.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6">
      <div
        className="fixed inset-0 bg-void/80 backdrop-blur-xs transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        className="relative z-10 max-h-[85vh] w-full max-w-2xl overflow-y-auto border border-signal/40 bg-panel p-5 shadow-2xl rise-in space-y-3"
      >
        <div className="flex items-center justify-between border-b border-line pb-2">
          <span className="font-display text-xs font-bold uppercase tracking-wider text-signal">
            Editing: {detail.title}
          </span>
          <button
            ref={closeButtonRef}
            type="button"
            onClick={onClose}
            className="border border-line bg-void/60 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:border-drop hover:text-drop cursor-pointer"
          >
            ✕ Close
          </button>
        </div>

      {detail.kind === 'target' && (
        <TargetLabelEditor
          namespace={policy.namespace}
          labels={policy.targetLabels}
          onUpdate={onUpdateTargetLabels}
        />
      )}

      {detail.kind === 'ingress-add' && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-ink-dim">
            {policy.ingressRules.length === 0
              ? 'All ingress is blocked by default until a rule allows it.'
              : 'Add another ingress source — blank or from a preset.'}
          </p>
          <AddRuleMenu
            label="Add Ingress Rule"
            presets={ingressPresets}
            onAddBlank={() => onAddIngress()}
            onAddPreset={(preset) => onAddIngress({ ...preset.rule, id: `ingress-${Date.now()}` })}
          />
        </div>
      )}

      {detail.kind === 'egress-add' && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-ink-dim">
            {policy.egressRules.length === 0
              ? 'All egress is allowed by default until a rule is added to restrict it.'
              : 'Add another egress destination — blank or from a preset.'}
          </p>
          <AddRuleMenu
            label="Add Egress Rule"
            presets={egressPresets}
            onAddBlank={() => onAddEgress()}
            onAddPreset={(preset) => onAddEgress({ ...preset.rule, id: `egress-${Date.now()}` })}
          />
        </div>
      )}

      {detail.kind === 'ingress' && detail.rule && (
        <RuleEditorCard
          ruleNumber={policy.ingressRules.findIndex((r) => r.id === detail.rule!.id) + 1}
          type="ingress"
          rule={detail.rule}
          targetNamespace={policy.namespace}
          targetLabels={policy.targetLabels}
          availableNamespaces={availableNamespaces}
          onUpdate={(updated) => onUpdateIngressRule(detail.rule!.id, updated as IngressRule)}
          onRemove={() => onRemoveIngress(detail.rule!.id)}
        />
      )}

      {detail.kind === 'egress' && detail.rule && (
        <RuleEditorCard
          ruleNumber={policy.egressRules.findIndex((r) => r.id === detail.rule!.id) + 1}
          type="egress"
          rule={detail.rule}
          targetNamespace={policy.namespace}
          targetLabels={policy.targetLabels}
          availableNamespaces={availableNamespaces}
          onUpdate={(updated) => onUpdateEgressRule(detail.rule!.id, updated as EgressRule)}
          onRemove={() => onRemoveEgress(detail.rule!.id)}
        />
      )}
      </div>
    </div>
  )
}

// Editable endpointSelector for the target workload node — the target's
// own namespace is already known (policy.namespace), so picking a running
// workload from the cluster needs no extra namespace input, unlike peer
// pickers which can point at any namespace.
function TargetLabelEditor({
  namespace,
  labels,
  onUpdate,
}: {
  namespace: string
  labels: Record<string, string>
  onUpdate: (labels: Record<string, string>) => void
}) {
  const [pickerOpen, setPickerOpen] = useState(false)
  const { byNamespace, loading } = useNamespacePods(pickerOpen && namespace ? [namespace] : [])
  const groups = useMemo(() => groupPodsBySignature(byNamespace[namespace] ?? []), [byNamespace, namespace])
  const pickerTriggerRef = useRef<HTMLButtonElement>(null)
  const pickerPos = useAnchoredPosition(pickerTriggerRef, pickerOpen)

  function handleAddLabel() {
    onUpdate({ ...labels, '': '' })
  }

  function handleUpdateLabel(oldKey: string, newKey: string, value: string) {
    const next: Record<string, string> = {}
    for (const [k, v] of Object.entries(labels)) {
      next[k === oldKey ? newKey : k] = k === oldKey ? value : v
    }
    onUpdate(next)
  }

  function handleRemoveLabel(key: string) {
    const next = { ...labels }
    delete next[key]
    onUpdate(next)
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
          endpointSelector.matchLabels {namespace && <>in <span className="text-ink">{namespace}</span></>}
        </label>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleAddLabel}
            className="text-[0.65rem] text-signal hover:underline cursor-pointer"
          >
            + Add Label
          </button>
          <div className="relative">
            <button
              ref={pickerTriggerRef}
              type="button"
              onClick={() => setPickerOpen((v) => !v)}
              disabled={!namespace}
              title={namespace ? `Pick a running workload in ${namespace}` : 'Set a namespace first'}
              className="border border-line bg-void/60 px-2 py-1 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:border-signal cursor-pointer disabled:cursor-not-allowed disabled:opacity-30"
            >
              ⌖ Pick From Cluster ▾
            </button>
            {pickerOpen && pickerPos && (
              <>
                <div className="fixed inset-0 z-20" onClick={() => setPickerOpen(false)} />
                <div
                  className="fixed z-30 w-72 max-h-64 overflow-y-auto border border-line-bright bg-panel-raised shadow-lg"
                  style={{ top: pickerPos.top, right: pickerPos.right }}
                >
                  {loading && groups.length === 0 && (
                    <div className="px-3 py-2 text-xs text-ink-dim">Loading pods in {namespace}…</div>
                  )}
                  {!loading && groups.length === 0 && (
                    <div className="px-3 py-2 text-xs text-ink-faint italic">
                      No labeled pods found in {namespace}
                    </div>
                  )}
                  {groups.map((g) => (
                    <button
                      key={JSON.stringify(g.signature)}
                      type="button"
                      onClick={() => {
                        onUpdate(g.signature)
                        setPickerOpen(false)
                      }}
                      className="flex w-full items-center justify-between gap-2 border-b border-line px-3 py-2 text-left last:border-b-0 hover:bg-signal/10 cursor-pointer"
                    >
                      <span className="flex flex-wrap gap-1">
                        {Object.entries(g.signature).map(([k, v]) => (
                          <span key={k} className="font-mono text-[0.65rem] text-ink">
                            {k}={v}
                          </span>
                        ))}
                      </span>
                      <span className="shrink-0 text-[0.6rem] text-ink-faint">
                        {g.count} pod{g.count === 1 ? '' : 's'}
                      </span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="space-y-2">
        {Object.entries(labels).map(([k, v], idx) => (
          <div key={idx} className="flex items-center gap-2">
            <input
              type="text"
              value={k}
              placeholder="label key"
              onChange={(e) => handleUpdateLabel(k, e.target.value, v)}
              className="flex-1 border border-line bg-void px-2.5 py-1.5 text-xs text-ink font-mono focus:border-signal focus:outline-none"
            />
            <span className="text-ink-dim font-bold">=</span>
            <input
              type="text"
              value={v}
              placeholder="value"
              onChange={(e) => handleUpdateLabel(k, k, e.target.value)}
              className="flex-1 border border-line bg-void px-2.5 py-1.5 text-xs text-ink font-mono focus:border-signal focus:outline-none"
            />
            <button
              type="button"
              onClick={() => handleRemoveLabel(k)}
              className="px-2 py-1 text-xs text-ink-dim hover:text-drop cursor-pointer"
              title="Remove label"
            >
              ✕
            </button>
          </div>
        ))}
        {Object.keys(labels).length === 0 && (
          <p className="text-xs text-ink-faint italic">
            No labels specified — matches all workloads in namespace (
            <code className="text-signal">matchLabels: &#123;&#125;</code>).
          </p>
        )}
      </div>
    </div>
  )
}

// Small icon badges summarizing what kinds of peers a rule has configured —
// {} for workload/pod labels, 🌐 for world/CIDR (anything outside the
// cluster), ⎈ for the cluster entity, 🖥 for the host entity — echoing
// editor.networkpolicy.io's "Outside Cluster / In Namespace / In Cluster"
// card vocabulary within this app's own node boxes.
function peerIcons(hasPeers: boolean, entities: string[], hasCidrs: boolean): string {
  const icons: string[] = []
  if (hasPeers) icons.push('{}')
  if (entities.includes('cluster')) icons.push('⎈')
  if (entities.includes('host')) icons.push('🖥')
  if (entities.includes('world') || hasCidrs) icons.push('🌐')
  return icons.join(' ')
}

function buildGraph(
  policy: PolicyModel,
  theme: 'dark' | 'light',
  containerWidth: number
): { initialNodes: Node[]; initialEdges: CustomEdge[] } {
  const signalColor = theme === 'dark' ? '#22e9c7' : '#0891b2'
  const allowColor = theme === 'dark' ? '#5ee8a5' : '#15803d'
  const { ingress: COLUMN_X_INGRESS, target: COLUMN_X_TARGET, egress: COLUMN_X_EGRESS } =
    computeColumnX(containerWidth)

  const targetLabels = Object.entries(policy.targetLabels)
    .filter(([k]) => k.trim())
    .map(([k, v]) => `${k}=${v}`)
    .join(', ') || 'matchLabels: {}'

  // Center Target Node
  const targetNodeId = 'target-workload'
  const targetBaseClass =
    BASE_NODE_CLASS +
    ' !border-signal !bg-[var(--color-panel-raised)] !text-[var(--color-ink)] ring-1 ring-signal/50'
  const targetLabel = (
    <div>
      <div className="flex items-center justify-between text-[0.65rem] font-semibold uppercase tracking-wider text-signal mb-1">
        <span>🎯 Target Workload</span>
        <span className="text-ink-faint normal-case">✎ edit</span>
      </div>
      <div className="text-xs font-bold text-ink">{targetLabels}</div>
      {policy.namespace && (
        <div className="text-[0.65rem] text-ink-dim mt-0.5">ns: {policy.namespace}</div>
      )}
      <div className="mt-1.5 flex gap-1 text-[0.6rem]">
        <span className="border border-drop/30 bg-drop/10 px-1 text-drop">
          Ingress: {policy.ingressRules.length > 0 ? 'Managed' : 'Default Deny'}
        </span>
        <span className="border border-line bg-panel px-1 text-ink-dim">
          Egress: {policy.egressRules.length > 0 ? 'Managed' : 'Default Allow'}
        </span>
      </div>
    </div>
  )

  const targetDetail: NodeDetail = {
    title: 'Target Workload',
    kind: 'target',
    namespace: policy.namespace,
  }

  const initialNodes: Node[] = [
    {
      id: targetNodeId,
      position: { x: COLUMN_X_TARGET, y: 40 },
      data: { label: targetLabel, detail: targetDetail, baseClass: targetBaseClass },
      className: targetBaseClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    },
  ]

  const initialEdges: CustomEdge[] = []

  const addNodeClass =
    BASE_NODE_CLASS +
    ' !border-dashed !border-line-bright !bg-panel/40 !text-ink-dim hover:!border-signal hover:!text-signal'
  const emptyDenyClass = BASE_NODE_CLASS + ' !border-dashed !border-drop/40 !bg-drop/5 !text-drop'
  const emptyAllowClass = BASE_NODE_CLASS + ' !border-dashed !border-line-bright !bg-panel/40 !text-ink-dim'

  // Ingress column: one node per rule, plus a trailing "+" node to add
  // another (or the first) rule — always present, not just when empty, so
  // adding rule #2/#3/… never requires leaving the graph.
  policy.ingressRules.forEach((rule, idx) => {
    const ruleId = `ingress-${rule.id}`
    const endpoints = rule.fromEndpoints
      .map((ep) => {
        const lbs = Object.entries(ep.matchLabels).map(([k, v]) => `${k}=${v}`).join(', ')
        return ep.namespace ? `${lbs} (ns: ${ep.namespace})` : lbs
      })
      .join('; ')
    const cidrs = rule.fromCIDRs.join(', ')
    const entities = rule.fromEntities.join(', ')
    const desc = [endpoints, cidrs ? `CIDR: ${cidrs}` : '', entities ? `Entities: ${entities}` : '']
      .filter(Boolean)
      .join(' | ') || 'From any peer'
    const icons = peerIcons(rule.fromEndpoints.length > 0, rule.fromEntities, rule.fromCIDRs.length > 0)
    const noOutput = ruleProducesNoOutput(rule)
    const warning = noOutput
      ? '⚠ no effect — rule emits nothing'
      : ruleHasNoEffectiveSelector(rule)
      ? '⚠ matches everything'
      : null

    const baseClass =
      BASE_NODE_CLASS +
      (warning
        ? ' !border-allow/60 !bg-allow/10 !text-[var(--color-ink)]'
        : ' !border-[var(--color-line-bright)] !bg-[var(--color-panel-raised)] !text-[var(--color-ink)]')

    initialNodes.push({
      id: ruleId,
      position: { x: COLUMN_X_INGRESS, y: idx * ROW_HEIGHT },
      data: {
        label: (
          <div>
            <div className="text-[0.65rem] font-semibold text-signal uppercase tracking-wider mb-0.5">
              {icons && <span className="mr-1">{icons}</span>}Ingress Source #{idx + 1}
            </div>
            <div className="text-xs font-semibold text-ink line-clamp-2">{desc}</div>
            {warning && (
              <div className="mt-1 text-[0.6rem] font-bold uppercase tracking-wider text-allow">{warning}</div>
            )}
          </div>
        ),
        detail: {
          title: `Ingress Source #${idx + 1}`,
          kind: 'ingress',
          namespace: policy.namespace,
          rule,
        } satisfies NodeDetail,
        baseClass,
      },
      className: baseClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })

    const portsLabel = rule.toPorts.length > 0
      ? rule.toPorts.map((p) => `${p.protocol}:${p.port}`).join(', ')
      : 'ANY'

    initialEdges.push({
      id: `edge-${ruleId}->${targetNodeId}`,
      type: 'policyEdge',
      source: ruleId,
      target: targetNodeId,
      data: {
        label: portsLabel,
        color: allowColor,
        isDimmed: false,
        direction: 'ingress',
      },
    })
  })

  const ingressAddClass = policy.ingressRules.length === 0 ? emptyDenyClass : addNodeClass
  initialNodes.push({
    id: 'ingress-add',
    position: { x: COLUMN_X_INGRESS, y: policy.ingressRules.length * ROW_HEIGHT },
    data: {
      label: (
        <div className="text-center">
          {policy.ingressRules.length === 0 ? (
            <>
              <div className="text-[0.65rem] font-semibold uppercase tracking-wider mb-0.5">Ingress Traffic</div>
              <div className="text-xs">+ Default Deny — click to add a rule</div>
            </>
          ) : (
            <div className="text-xs font-semibold">+ Add Ingress Rule</div>
          )}
        </div>
      ),
      detail: { title: 'Add Ingress Rule', kind: 'ingress-add' } satisfies NodeDetail,
      baseClass: ingressAddClass,
    },
    className: ingressAddClass,
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  })

  // Egress column: same pattern, mirrored.
  policy.egressRules.forEach((rule, idx) => {
    const ruleId = `egress-${rule.id}`
    const endpoints = rule.toEndpoints
      .map((ep) => {
        const lbs = Object.entries(ep.matchLabels).map(([k, v]) => `${k}=${v}`).join(', ')
        return ep.namespace ? `${lbs} (ns: ${ep.namespace})` : lbs
      })
      .join('; ')
    const cidrs = rule.toCIDRs.join(', ')
    const entities = rule.toEntities.join(', ')
    const desc = [endpoints, cidrs ? `CIDR: ${cidrs}` : '', entities ? `Entities: ${entities}` : '']
      .filter(Boolean)
      .join(' | ') || 'To any peer'
    const icons = peerIcons(rule.toEndpoints.length > 0, rule.toEntities, rule.toCIDRs.length > 0)
    const noOutput = ruleProducesNoOutput(rule)
    const warning = noOutput
      ? '⚠ no effect — rule emits nothing'
      : ruleHasNoEffectiveSelector(rule)
      ? '⚠ matches everything'
      : null

    const baseClass =
      BASE_NODE_CLASS +
      (warning
        ? ' !border-allow/60 !bg-allow/10 !text-[var(--color-ink)]'
        : ' !border-[var(--color-line-bright)] !bg-[var(--color-panel-raised)] !text-[var(--color-ink)]')

    initialNodes.push({
      id: ruleId,
      position: { x: COLUMN_X_EGRESS, y: idx * ROW_HEIGHT },
      data: {
        label: (
          <div>
            <div className="text-[0.65rem] font-semibold text-signal uppercase tracking-wider mb-0.5">
              {icons && <span className="mr-1">{icons}</span>}Egress Dest #{idx + 1}
            </div>
            <div className="text-xs font-semibold text-ink line-clamp-2">{desc}</div>
            {warning && (
              <div className="mt-1 text-[0.6rem] font-bold uppercase tracking-wider text-allow">{warning}</div>
            )}
          </div>
        ),
        detail: {
          title: `Egress Destination #${idx + 1}`,
          kind: 'egress',
          namespace: policy.namespace,
          rule,
        } satisfies NodeDetail,
        baseClass,
      },
      className: baseClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })

    const portsLabel = rule.toPorts.length > 0
      ? rule.toPorts.map((p) => `${p.protocol}:${p.port}`).join(', ')
      : 'ANY'

    initialEdges.push({
      id: `edge-${targetNodeId}->${ruleId}`,
      type: 'policyEdge',
      source: targetNodeId,
      target: ruleId,
      data: {
        label: portsLabel,
        color: signalColor,
        isDimmed: false,
        direction: 'egress',
      },
    })
  })

  const egressAddClass = policy.egressRules.length === 0 ? emptyAllowClass : addNodeClass
  initialNodes.push({
    id: 'egress-add',
    position: { x: COLUMN_X_EGRESS, y: policy.egressRules.length * ROW_HEIGHT },
    data: {
      label: (
        <div className="text-center">
          {policy.egressRules.length === 0 ? (
            <>
              <div className="text-[0.65rem] font-semibold uppercase tracking-wider mb-0.5">Egress Traffic</div>
              <div className="text-xs">+ Default Allow — click to restrict</div>
            </>
          ) : (
            <div className="text-xs font-semibold">+ Add Egress Rule</div>
          )}
        </div>
      ),
      detail: { title: 'Add Egress Rule', kind: 'egress-add' } satisfies NodeDetail,
      baseClass: egressAddClass,
    },
    className: egressAddClass,
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  })

  return { initialNodes, initialEdges }
}
