// Node/flow diagram for verdict results with interactive node-level filtering
// and anti-collision staggered edge labels.
//
// Selection behavior:
// - Clicking any source or destination box isolates all traffic touching that box.
// - Unrelated boxes and flows are dimmed out to easily trace single-workload blast radius.
// - Clicking again or clicking the background resets the view.
//
// Anti-collision label behavior:
// - Edge labels are rendered with EdgeLabelRenderer in solid badge containers so
//   traffic paths never cut through text.
// - Labels are staggered along the cubic bezier curve to eliminate visual bottlenecks.
// - Multi-port flows between the same endpoints are consolidated into single clean badges.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  BaseEdge,
  Controls,
  EdgeLabelRenderer,
  getBezierPath,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeChange,
  type NodeProps,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { VerdictChange, VerdictRow } from '../api'
import { useTheme } from '../theme'
import { NodeLabelsPanel } from './NodeLabelsPanel'

const EDGE_COLORS: Record<'dark' | 'light', Record<VerdictChange, string>> = {
  dark: {
    NEWLY_DROPPED: '#ff5d5d',
    NEWLY_ALLOWED: '#ffb648',
    UNCHANGED: '#5ee8a5',
  },
  light: {
    NEWLY_DROPPED: '#dc2626',
    NEWLY_ALLOWED: '#b45309',
    UNCHANGED: '#15803d',
  },
}

const BASE_NODE_CLASS =
  '!w-[240px] !whitespace-normal !break-words !rounded-none !border !px-3 !py-2.5 !text-xs !font-mono cursor-pointer transition-all duration-200 select-none'

const ROW_HEIGHT = 130
const NODE_WIDTH = 240
// Fallback column gap for the one frame before ResizeObserver reports a real
// container width (buildGraph is called with containerWidth=0 then).
const FALLBACK_COLUMN_GAP = 780
// Fraction of measured container width kept clear on each side so columns
// span close to the full canvas instead of a fixed, viewport-independent gap.
const COLUMN_MARGIN_FRACTION = 0.04

interface VerdictEdgeData {
  change: VerdictChange
  label: string
  color: string
  labelT: number
  isDimmed: boolean
  [key: string]: unknown
}

type CustomEdge = Edge<VerdictEdgeData, 'verdict'>

// Calculates an explicit coordinate along a cubic bezier curve given parameter t in [0, 1]
function getBezierPoint(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  t: number,
  curvature: number = 0.25
): [number, number] {
  const dx = (targetX - sourceX) * curvature
  const p0 = [sourceX, sourceY]
  const p1 = [sourceX + dx, sourceY]
  const p2 = [targetX - dx, targetY]
  const p3 = [targetX, targetY]

  const mt = 1 - t
  const mt2 = mt * mt
  const mt3 = mt2 * mt
  const t2 = t * t
  const t3 = t2 * t

  const x = mt3 * p0[0] + 3 * mt2 * t * p1[0] + 3 * mt * t2 * p2[0] + t3 * p3[0]
  const y = mt3 * p0[1] + 3 * mt2 * t * p1[1] + 3 * mt * t2 * p2[1] + t3 * p3[1]

  return [x, y]
}

// Edges spanning many rows get more curvature so they sweep around the
// dense horizontal midline instead of cutting straight through it, reducing
// crossing density on graphs with many flows — a straight/near-straight edge
// between adjacent rows keeps its curvature small.
function computeCurvature(sourceY: number, targetY: number): number {
  const rowDistance = Math.abs(targetY - sourceY) / ROW_HEIGHT
  return Math.min(0.6, 0.15 + rowDistance * 0.08)
}

function VerdictEdgeComponent({
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
  const curvature = computeCurvature(sourceY, targetY)

  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    curvature,
  })

  const t = data?.labelT ?? 0.5
  const [labelX, labelY] = getBezierPoint(sourceX, sourceY, targetX, targetY, t, curvature)
  const isDimmed = data?.isDimmed ?? false
  const color = data?.color ?? '#5ee8a5'

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          ...style,
          stroke: color,
          strokeWidth: isDimmed ? 1 : 2,
          opacity: isDimmed ? 0.08 : 1,
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
            className={`z-10 flex items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[11px] font-semibold tracking-tight shadow-xs select-none backdrop-blur-xs ${
              data.change === 'NEWLY_DROPPED'
                ? 'border-drop/40 bg-panel text-drop shadow-[0_1px_3px_rgba(220,38,38,0.1)]'
                : data.change === 'NEWLY_ALLOWED'
                ? 'border-allow/40 bg-panel text-allow shadow-[0_1px_3px_rgba(217,119,6,0.1)]'
                : 'border-unchanged/40 bg-panel text-unchanged shadow-[0_1px_3px_rgba(22,163,74,0.1)]'
            }`}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

const edgeTypes = {
  verdict: VerdictEdgeComponent,
}

// Kubernetes pod names follow <workload>-<10-char-replicaset-hash>-<5-char-pod-hash>;
// detect that shape so only the generated suffix gets truncated, rather than
// a fixed character count that would mis-truncate short, hand-picked names.
const POD_HASH_SUFFIX = /^(.+)-([a-z0-9]{8,10})-([a-z0-9]{5})$/

function truncateWorkloadName(name: string): string {
  const match = name.match(POD_HASH_SUFFIX)
  if (!match) return name
  const [, prefix, , podHash] = match
  return `${prefix}-…${podHash.slice(-4)}`
}

function parseNodeLabel(raw: string): { namespace: string | null; workload: string } {
  const slashIndex = raw.indexOf('/')
  if (slashIndex === -1) return { namespace: null, workload: raw }
  return { namespace: raw.slice(0, slashIndex), workload: raw.slice(slashIndex + 1) }
}

// Custom node renderer so a real label like
// "observability/prometheus-snmp-exporter-76b49d99df-rgq8m" gets visual
// hierarchy (dim namespace, bold workload name, truncated hash) instead of
// one undifferentiated string — the full label stays available via `title`
// for hover. Handles are drawn manually since overriding the node type opts
// out of xyflow's default node rendering (which draws them automatically).
function WorkloadNode({ data, sourcePosition, targetPosition }: NodeProps) {
  const label = (data as { label?: string }).label ?? ''
  const { namespace, workload } = parseNodeLabel(label)

  return (
    <>
      <Handle type="target" position={targetPosition ?? Position.Left} />
      <div title={label} className="flex flex-col gap-0.5">
        {namespace && <span className="block text-ink-dim text-[10px] leading-tight">{namespace}</span>}
        <span className="block text-ink font-semibold leading-tight">{truncateWorkloadName(workload)}</span>
      </div>
      <Handle type="source" position={sourcePosition ?? Position.Right} />
    </>
  )
}

const nodeTypes = {
  workload: WorkloadNode,
}

interface VerdictGraphProps {
  rows: VerdictRow[]
  // Selection is controlled by the parent (RunCard) so clicking a table row
  // can select the same node a box click would — "src:<name>" or
  // "dst:<name>", matching buildGraph's own node id scheme below.
  selectedNodeId: string | null
  onSelectNode: (id: string | null) => void
}

export function VerdictGraph({ rows, selectedNodeId, onSelectNode }: VerdictGraphProps) {
  const { theme } = useTheme()

  // Container ref so column X-positions can be derived from the actual
  // rendered width instead of a fixed pixel gap — otherwise fitView ends up
  // fitting a narrow fixed-width layout into a much wider viewport, leaving
  // large dead margins on either side at wide viewports.
  const containerRef = useRef<HTMLDivElement>(null)
  const [containerWidth, setContainerWidth] = useState(0)
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const observer = new ResizeObserver((entries) => {
      const width = entries[0]?.contentRect.width
      if (width) setContainerWidth(width)
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // User-dragged node positions, keyed by node id, layered on top of the
  // auto-layout buildGraph computes — so repositioning a box survives
  // buildGraph re-running whenever rows/theme change.
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

  const { initialNodes: laidOutNodes, initialEdges } = useMemo(
    () => buildGraph(rows, theme, containerWidth),
    [rows, theme, containerWidth]
  )

  // <ReactFlow fitView /> only auto-fits the camera once, on first mount —
  // it does NOT re-fit when the nodes prop later changes. This graph's own
  // first mount typically happens with containerWidth still 0 (the
  // ResizeObserver above hasn't reported yet), so buildGraph lays nodes out
  // using the narrow FALLBACK_COLUMN_GAP and the initial auto-fit zooms to
  // that. The moment a real width comes in (and in "Follow (live)" mode,
  // every time a new row streams in and shifts the layout), buildGraph
  // recomputes correct, much-wider-spread node positions — but the camera
  // never moves to match, so the actual nodes render outside the still-
  // fitted-to-the-old-layout viewport: a graph with real data that looks
  // completely empty. Re-running fitView whenever the computed layout
  // changes keeps the camera honest.
  useEffect(() => {
    if (!rfInstance || laidOutNodes.length === 0) return
    rfInstance.fitView({ padding: 0.25 })
  }, [rfInstance, laidOutNodes])

  const initialNodes = useMemo(
    () =>
      laidOutNodes.map((node) =>
        dragPositions[node.id] ? { ...node, position: dragPositions[node.id] } : node
      ),
    [laidOutNodes, dragPositions]
  )

  // Filter edges and nodes based on selectedNodeId
  const { nodes, edges, selectedNodeName } = useMemo(() => {
    if (!selectedNodeId) {
      return {
        nodes: initialNodes,
        edges: initialEdges,
        selectedNodeName: null,
      }
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

    const selectedNode = initialNodes.find((n) => n.id === selectedNodeId)
    const selectedNodeName = (selectedNode?.data as { label?: string })?.label || selectedNodeId

    const updatedNodes = initialNodes.map((node) => {
      const isSelected = node.id === selectedNodeId
      const isConnected = connectedNodeIds.has(node.id)

      let className = BASE_NODE_CLASS
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

      return {
        ...node,
        className,
      }
    })

    const updatedEdges = initialEdges.map((edge) => {
      const isConnected = connectedEdgeIds.has(edge.id)
      return {
        ...edge,
        animated: isConnected && edge.data?.change !== 'UNCHANGED',
        zIndex: isConnected ? 10 : 0,
        data: {
          ...edge.data!,
          isDimmed: !isConnected,
        },
      }
    })

    return {
      nodes: updatedNodes,
      edges: updatedEdges,
      selectedNodeName,
    }
  }, [initialNodes, initialEdges, selectedNodeId])

  if (rows.length === 0) return null

  const height = Math.max(480, Math.min(960, Math.max(nodes.length, 3) * (ROW_HEIGHT / 1.05)))
  // A large node count (common in follow mode, where every live event adds
  // an undeduplicated row) needs to zoom out further than a fixed 0.3 floor
  // allows to fit everything — without this, "Fit View" silently clips most
  // of the graph outside the visible/pannable area, which looks like the
  // graph failed to render rather than just being dense.
  const minZoom = Math.max(0.02, Math.min(0.3, height / (Math.max(nodes.length, 1) * ROW_HEIGHT)))

  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase">
        <div className="flex items-center gap-2 flex-1">
          <span className="h-px flex-1 bg-line" />
          Flow graph
          <span className="h-px flex-1 bg-line" />
        </div>
      </div>

      {selectedNodeName && (
        <div className="mb-2 flex items-center justify-between border border-signal/30 bg-signal/10 px-3 py-1.5 text-xs text-ink rise-in">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 rounded-full bg-signal" />
            <span>
              Isolating flows for: <strong className="font-mono text-signal">{selectedNodeName}</strong>
            </span>
          </div>
          <button
            type="button"
            onClick={() => onSelectNode(null)}
            className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-signal cursor-pointer"
          >
            Show all (clear filter)
          </button>
        </div>
      )}

      {selectedNodeName && <NodeLabelsPanel nodeName={selectedNodeName} />}

      <div className="border border-line bg-void relative" style={{ height }} ref={containerRef}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onInit={setRfInstance}
          onNodesChange={handleNodesChange}
          onNodeClick={(_, node) => onSelectNode(selectedNodeId === node.id ? null : node.id)}
          onPaneClick={() => onSelectNode(null)}
          fitView
          fitViewOptions={{ padding: 0.25 }}
          proOptions={{ hideAttribution: true }}
          colorMode={theme}
          minZoom={minZoom}
        >
          <Background
            variant={BackgroundVariant.Dots}
            gap={22}
            size={1}
            color={theme === 'dark' ? '#1c2b2c' : '#d0dddc'}
          />
          <Controls
            className="!border !border-[var(--color-line)] !bg-[var(--color-panel)] [&_button]:!border-[var(--color-line)] [&_button]:!bg-[var(--color-panel-raised)] [&_button]:!fill-[var(--color-ink)] [&_button:hover]:!bg-[var(--color-line)]"
            showInteractive={false}
          />
        </ReactFlow>
      </div>
    </div>
  )
}

function buildGraph(
  rows: VerdictRow[],
  theme: 'dark' | 'light',
  containerWidth: number
): { initialNodes: Node[]; initialEdges: CustomEdge[] } {
  const colors = EDGE_COLORS[theme]
  const sources = Array.from(new Set(rows.map((r) => r.source))).sort()
  const destinations = Array.from(new Set(rows.map((r) => r.destination))).sort()

  const defaultNodeClass =
    BASE_NODE_CLASS +
    ' !border-[var(--color-line-bright)] !bg-[var(--color-panel-raised)] !text-[var(--color-ink)] !shadow-[0_0_0_1px_var(--color-signal-glow)]'

  // Source column near the left edge, destination column near the right
  // edge, both as fractions of the measured container width so the graph
  // spans close to the full canvas at any viewport size instead of a fixed
  // pixel gap. Falls back to the old fixed gap for the one frame before
  // ResizeObserver reports a real width.
  const margin = containerWidth * COLUMN_MARGIN_FRACTION
  const sourceX = containerWidth ? margin : 0
  const destX = containerWidth
    ? Math.max(sourceX + NODE_WIDTH + 40, containerWidth - margin - NODE_WIDTH)
    : FALLBACK_COLUMN_GAP

  const initialNodes: Node[] = [
    ...sources.map((name, i) => ({
      id: `src:${name}`,
      type: 'workload',
      position: { x: sourceX, y: i * ROW_HEIGHT },
      data: { label: name },
      className: defaultNodeClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })),
    ...destinations.map((name, i) => ({
      id: `dst:${name}`,
      type: 'workload',
      position: { x: destX, y: i * ROW_HEIGHT },
      data: { label: name },
      className: defaultNodeClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })),
  ]

  // Group flows by (source, destination, change) to avoid duplicate stacked bezier curves
  // while consolidating distinct ports into a clear badge label.
  type AggregatedEdge = {
    change: VerdictChange
    source: string
    destination: string
    ports: Map<string, number> // e.g. "TCP:80" -> count
  }

  const edgeMap = new Map<string, AggregatedEdge>()

  for (const row of rows) {
    const key = `${row.change}|${row.source}|${row.destination}`
    const existing = edgeMap.get(key)
    const portKey = `${row.protocol}:${row.port}`
    if (existing) {
      existing.ports.set(portKey, (existing.ports.get(portKey) || 0) + row.count)
    } else {
      const ports = new Map<string, number>()
      ports.set(portKey, row.count)
      edgeMap.set(key, {
        change: row.change,
        source: row.source,
        destination: row.destination,
        ports,
      })
    }
  }

  // Pre-calculated staggering offsets along the curve so labels don't bunch at t=0.5
  const STAGGER_OFFSETS = [0.42, 0.58, 0.34, 0.66, 0.50, 0.46, 0.62]

  const initialEdges: CustomEdge[] = Array.from(edgeMap.entries()).map(([key, agg], index) => {
    const labelParts = Array.from(agg.ports.entries()).map(([port, count]) =>
      count > 1 ? `${port} ×${count}` : port
    )
    const label = labelParts.join(', ')
    const labelT = STAGGER_OFFSETS[index % STAGGER_OFFSETS.length]

    return {
      id: `edge-${key}`,
      type: 'verdict',
      source: `src:${agg.source}`,
      target: `dst:${agg.destination}`,
      animated: agg.change !== 'UNCHANGED',
      data: {
        change: agg.change,
        label,
        color: colors[agg.change],
        labelT,
        isDimmed: false,
      },
    }
  })

  return { initialNodes, initialEdges }
}
