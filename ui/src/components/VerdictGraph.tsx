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
//
// Look: the connectivity test's path diagram (GraphPathParts.tsx) — round
// endpoint nodes; links that flow through, or stop at a ✕ gate when the
// candidate blocks them. Only changed links (and the selected node's) move.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Position,
  ReactFlow,
  type Node,
  type NodeChange,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { VerdictChange, VerdictRow } from '../api'
import { useTheme } from '../theme'
import { graphTooLarge } from '../shared/graphBudget'
import { GraphPlaceholder } from './GraphPlaceholder'
import { NodeLabelsPanel } from './NodeLabelsPanel'
import { EndpointNode, makePathEdge, type EndpointData, type PathEdgeData, type PathEdgeType } from './GraphPathParts'

const EDGE_COLORS: Record<'dark' | 'light', Record<VerdictChange | 'BLOCKED', string>> = {
  dark: {
    NEWLY_DROPPED: '#ff5d5d',
    NEWLY_ALLOWED: '#ffb648',
    L7_CHANGED: '#c4a1ff',
    UNCHANGED: '#5ee8a5',
    BLOCKED: '#7b9799',
  },
  light: {
    NEWLY_DROPPED: '#dc2626',
    NEWLY_ALLOWED: '#b45309',
    L7_CHANGED: '#7c3aed',
    UNCHANGED: '#15803d',
    BLOCKED: '#527072',
  },
}

const NODE_CLASS = 'cursor-pointer select-none'

const ROW_HEIGHT = 130
const NODE_WIDTH = 240
// Fallback column gap for the one frame before ResizeObserver reports a real
// container width (buildGraph is called with containerWidth=0 then).
const FALLBACK_COLUMN_GAP = 780
// Fraction of measured container width kept clear on each side so columns
// span close to the full canvas instead of a fixed, viewport-independent gap.
const COLUMN_MARGIN_FRACTION = 0.04

type CustomEdge = PathEdgeType

const BADGE_CLASSES: Record<VerdictChange | 'BLOCKED', string> = {
  NEWLY_DROPPED: 'border-drop/40 text-drop',
  NEWLY_ALLOWED: 'border-allow/40 text-allow',
  L7_CHANGED: 'border-l7/40 text-l7',
  UNCHANGED: 'border-unchanged/40 text-unchanged',
  BLOCKED: 'border-line-bright text-ink-dim',
}

const edgeTypes = {
  path: makePathEdge(ROW_HEIGHT),
}

const nodeTypes = {
  endpoint: EndpointNode,
}

interface VerdictGraphProps {
  rows: VerdictRow[]
  // Selection is controlled by the parent (RunCard) so clicking a table row
  // can select the same node a box click would — "src:<name>" or
  // "dst:<name>", matching buildGraph's own node id scheme below.
  selectedNodeId: string | null
  onSelectNode: (id: string | null) => void
}

// Size guard in front of the canvas: counts the exact nodes/edges buildGraph
// would produce and, past the limit, shows a placeholder instead of mounting
// React Flow (see shared/graphBudget.ts). A separate component rather than an
// early return inside the canvas, because the canvas measures its container
// once on mount — a container that only appears after "Draw anyway" would
// never be measured.
export function VerdictGraph({ hints, ...props }: VerdictGraphProps & { hints?: string[] }) {
  const { theme } = useTheme()
  const [drawAnyway, setDrawAnyway] = useState(false)
  const size = useMemo(() => {
    const g = buildGraph(props.rows, theme, 0)
    return { nodes: g.initialNodes.length, edges: g.initialEdges.length }
  }, [props.rows, theme])

  if (props.rows.length === 0) return null
  if (!drawAnyway && graphTooLarge(size.nodes, size.edges)) {
    return (
      <GraphPlaceholder
        reason="tooLarge"
        nodes={size.nodes}
        edges={size.edges}
        hints={hints}
        onDraw={() => setDrawAnyway(true)}
      />
    )
  }
  return <VerdictGraphCanvas {...props} />
}

function VerdictGraphCanvas({ rows, selectedNodeId, onSelectNode }: VerdictGraphProps) {
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

    const updatedNodes = initialNodes.map((node) => ({
      ...node,
      data: {
        ...(node.data as EndpointData),
        state: node.id === selectedNodeId ? 'selected' : connectedNodeIds.has(node.id) ? 'connected' : 'dimmed',
      },
      zIndex: node.id === selectedNodeId ? 20 : connectedNodeIds.has(node.id) ? 10 : 0,
    }))

    const updatedEdges = initialEdges.map((edge) => {
      const isConnected = connectedEdgeIds.has(edge.id)
      return {
        ...edge,
        zIndex: isConnected ? 10 : 0,
        data: {
          ...edge.data!,
          isDimmed: !isConnected,
          // Everything touching the selected node moves; the rest is dimmed.
          animate: isConnected,
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
      type: 'endpoint',
      position: { x: sourceX, y: i * ROW_HEIGHT },
      data: { label: name, side: 'src', state: 'normal' } satisfies EndpointData,
      className: NODE_CLASS,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })),
    ...destinations.map((name, i) => ({
      id: `dst:${name}`,
      type: 'endpoint',
      position: { x: destX, y: i * ROW_HEIGHT },
      data: { label: name, side: 'dst', state: 'normal' } satisfies EndpointData,
      className: NODE_CLASS,
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
    // UNCHANGED covers "still allowed" and "still blocked"; the link only
    // stops at a gate when the candidate blocks every row it aggregates.
    stillBlocked: boolean
  }

  const edgeMap = new Map<string, AggregatedEdge>()

  for (const row of rows) {
    const key = `${row.change}|${row.source}|${row.destination}`
    const existing = edgeMap.get(key)
    const portKey = `${row.protocol}:${row.port}`
    if (existing) {
      existing.ports.set(portKey, (existing.ports.get(portKey) || 0) + row.count)
      existing.stillBlocked &&= row.candidateAllowed === false
    } else {
      const ports = new Map<string, number>()
      ports.set(portKey, row.count)
      edgeMap.set(key, {
        change: row.change,
        source: row.source,
        destination: row.destination,
        ports,
        stillBlocked: row.candidateAllowed === false,
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

    const look: VerdictChange | 'BLOCKED' = agg.change === 'UNCHANGED' && agg.stillBlocked ? 'BLOCKED' : agg.change
    const data: PathEdgeData = {
      outcome: look === 'NEWLY_DROPPED' || look === 'BLOCKED' ? 'stop' : 'pass',
      color: colors[look],
      gate: look === 'NEWLY_DROPPED' || look === 'BLOCKED' ? '✕' : look === 'NEWLY_ALLOWED' ? '✓' : look === 'L7_CHANGED' ? 'L7' : undefined,
      badgeClass: BADGE_CLASSES[look],
      label,
      labelT,
      isDimmed: false,
      // Only what the candidate changes moves; unchanged links stay still.
      animate: agg.change !== 'UNCHANGED',
    }
    return {
      id: `edge-${key}`,
      type: 'path',
      source: `src:${agg.source}`,
      target: `dst:${agg.destination}`,
      data,
    }
  })

  return { initialNodes, initialEdges }
}
