// Node/flow diagram for raw Hubble flows with interactive node-level filtering,
// anti-collision staggered edge labels, and theme support.

import { useCallback, useMemo, useState } from 'react'
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
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { Flow } from '../api'
import { useTheme } from '../theme'
import { NodeLabelsPanel } from './NodeLabelsPanel'

const EDGE_COLORS: Record<'dark' | 'light', Record<string, string>> = {
  dark: {
    FORWARDED: '#5ee8a5',
    DROPPED: '#ff5d5d',
    AUDIT: '#ffb648',
    default: '#7b9799',
  },
  light: {
    FORWARDED: '#15803d',
    DROPPED: '#dc2626',
    AUDIT: '#b45309',
    default: '#527072',
  },
}

const BASE_NODE_CLASS =
  '!w-[240px] !whitespace-normal !break-words !rounded-none !border !px-3 !py-2.5 !text-xs !font-mono cursor-pointer transition-all duration-200 select-none'

const ROW_HEIGHT = 130
const COLUMN_GAP = 780

interface FlowEdgeData {
  verdict: string
  label: string
  fullLabel?: string
  color: string
  labelT: number
  isDimmed: boolean
  [key: string]: unknown
}

type CustomEdge = Edge<FlowEdgeData, 'flow'>

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

function FlowEdgeComponent({
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
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  })

  const t = data?.labelT ?? 0.5
  const [labelX, labelY] = getBezierPoint(sourceX, sourceY, targetX, targetY, t)
  const isDimmed = data?.isDimmed ?? false
  const color = data?.color ?? '#5ee8a5'
  const verdict = data?.verdict ?? 'FORWARDED'

  let badgeColorClass = 'border-line-bright bg-panel text-ink-dim'
  if (verdict === 'DROPPED') {
    badgeColorClass = 'border-drop/40 bg-panel text-drop shadow-[0_1px_3px_rgba(220,38,38,0.1)]'
  } else if (verdict === 'AUDIT') {
    badgeColorClass = 'border-allow/40 bg-panel text-allow shadow-[0_1px_3px_rgba(217,119,6,0.1)]'
  } else if (verdict === 'FORWARDED') {
    badgeColorClass = 'border-unchanged/40 bg-panel text-unchanged shadow-[0_1px_3px_rgba(22,163,74,0.1)]'
  }

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
            title={data.fullLabel || data.label}
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: isDimmed ? 'none' : 'all',
              opacity: isDimmed ? 0.05 : 1,
              transition: 'opacity 0.2s ease',
            }}
            className={`z-10 flex items-center gap-1 rounded-sm border px-2 py-0.5 font-mono text-[11px] font-semibold tracking-tight shadow-xs select-none backdrop-blur-xs ${badgeColorClass}`}
          >
            {data.label}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  )
}

const edgeTypes = {
  flow: FlowEdgeComponent,
}

interface FlowsGraphProps {
  flows: Flow[]
  // Selection is controlled by the parent (FlowRunCard) so clicking a table
  // row can select the same node a box click would — "src:<name>" or
  // "dst:<name>", matching buildGraph's own node id scheme below.
  selectedNodeId: string | null
  onSelectNode: (id: string | null) => void
}

export function FlowsGraph({ flows, selectedNodeId, onSelectNode }: FlowsGraphProps) {
  const { theme } = useTheme()

  // User-dragged node positions, keyed by node id, layered on top of the
  // auto-layout buildGraph computes — so repositioning a box survives
  // buildGraph re-running whenever flows/theme change.
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
    () => buildGraph(flows, theme),
    [flows, theme]
  )

  const initialNodes = useMemo(
    () =>
      laidOutNodes.map((node) =>
        dragPositions[node.id] ? { ...node, position: dragPositions[node.id] } : node
      ),
    [laidOutNodes, dragPositions]
  )

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
        animated: isConnected && edge.data?.verdict === 'DROPPED',
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

  if (flows.length === 0) return null

  const height = Math.max(480, Math.min(960, Math.max(nodes.length, 3) * (ROW_HEIGHT / 1.05)))
  // A large node count needs to zoom out further than a fixed 0.3 floor
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

      <div className="border border-line bg-void relative" style={{ height }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          edgeTypes={edgeTypes}
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
  flows: Flow[],
  theme: 'dark' | 'light'
): { initialNodes: Node[]; initialEdges: CustomEdge[] } {
  const colors = EDGE_COLORS[theme]
  const sources = Array.from(new Set(flows.map((f) => f.source))).sort()
  const destinations = Array.from(new Set(flows.map((f) => f.destination))).sort()

  const defaultNodeClass =
    BASE_NODE_CLASS +
    ' !border-[var(--color-line-bright)] !bg-[var(--color-panel-raised)] !text-[var(--color-ink)] !shadow-[0_0_0_1px_var(--color-signal-glow)]'

  const initialNodes: Node[] = [
    ...sources.map((name, i) => ({
      id: `src:${name}`,
      position: { x: 0, y: i * ROW_HEIGHT },
      data: { label: name },
      className: defaultNodeClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })),
    ...destinations.map((name, i) => ({
      id: `dst:${name}`,
      position: { x: COLUMN_GAP, y: i * ROW_HEIGHT },
      data: { label: name },
      className: defaultNodeClass,
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    })),
  ]

  // Group flows by (source, destination, verdict)
  type AggregatedEdge = {
    verdict: string
    source: string
    destination: string
    ports: Map<string, number> // e.g. "TCP:80" -> count
  }

  const edgeMap = new Map<string, AggregatedEdge>()

  for (const f of flows) {
    const verdict = f.verdict || 'FORWARDED'
    const key = `${verdict}|${f.source}|${f.destination}`
    const existing = edgeMap.get(key)
    const portKey = f.l4 || '-'
    if (existing) {
      existing.ports.set(portKey, (existing.ports.get(portKey) || 0) + 1)
    } else {
      const ports = new Map<string, number>()
      ports.set(portKey, 1)
      edgeMap.set(key, {
        verdict,
        source: f.source,
        destination: f.destination,
        ports,
      })
    }
  }

  // Pre-calculated staggering offsets along the curve
  const STAGGER_OFFSETS = [0.42, 0.58, 0.34, 0.66, 0.50, 0.46, 0.62]

  const initialEdges: CustomEdge[] = Array.from(edgeMap.entries()).map(([key, agg], index) => {
    const fullLabel = Array.from(agg.ports.entries())
      .map(([port, count]) => (count > 1 ? `${port} ×${count}` : port))
      .join(', ')

    const maxDisplayed = 3
    let label = fullLabel
    if (agg.ports.size > maxDisplayed) {
      const topPorts = Array.from(agg.ports.entries())
        .slice(0, maxDisplayed)
        .map(([port, count]) => (count > 1 ? `${port} ×${count}` : port))
      const remaining = agg.ports.size - maxDisplayed
      label = `${topPorts.join(', ')} (+${remaining} more)`
    }

    const labelT = STAGGER_OFFSETS[index % STAGGER_OFFSETS.length]
    const edgeColor = colors[agg.verdict] ?? colors.default

    return {
      id: `edge-${key}`,
      type: 'flow',
      source: `src:${agg.source}`,
      target: `dst:${agg.destination}`,
      animated: agg.verdict === 'DROPPED',
      data: {
        verdict: agg.verdict,
        label,
        fullLabel,
        color: edgeColor,
        labelT,
        isDimmed: false,
      },
    }
  })

  return { initialNodes, initialEdges }
}
