// The connectivity test's path-diagram look (ProbePath.tsx), as React Flow
// node and edge types shared by the Verdict and Flows graphs: round endpoint
// nodes labelled by peer kind, and links that either flow through to the
// destination or stop at a ✕ gate. React Flow still owns layout, pan/zoom
// and click-to-isolate; only how nodes and links are drawn lives here.
//
// Motion is reserved for what deserves attention — a link whose verdict
// changed, or every link of the selected node — never every edge at once,
// so a dense graph stays calm. Reduced-motion users get static dashes.

import { BaseEdge, EdgeLabelRenderer, Handle, Position, type Edge, type EdgeProps, type NodeProps } from '@xyflow/react'
import { cubicPath, endpointKind, linkCurve, pointAt, splitAt } from '../shared/graphPath'

export type EndpointState = 'normal' | 'selected' | 'connected' | 'dimmed'

export interface EndpointData {
  label: string
  side: 'src' | 'dst'
  state?: EndpointState
  [key: string]: unknown
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
  if (slashIndex === -1 || raw.startsWith('reserved:')) return { namespace: null, workload: raw }
  return { namespace: raw.slice(0, slashIndex), workload: raw.slice(slashIndex + 1) }
}

const ringByState: Record<EndpointState, string> = {
  normal: 'border-line-bright',
  connected: 'border-line-bright shadow-[0_0_0_3px_var(--color-signal-glow)]',
  selected: 'border-signal shadow-[0_0_14px_var(--color-signal-glow)] ring-2 ring-signal',
  dimmed: 'border-line',
}

// Circle on the inner side (facing the links), name on the outer side, so a
// source column reads "name (●)──▶" and a destination "──▶(●) name". The full
// label stays available via `title` for hover.
export function EndpointNode({ data }: NodeProps) {
  const { label, side, state = 'normal' } = data as EndpointData
  const { namespace, workload } = parseNodeLabel(label)
  const kind = endpointKind(label)
  const circle = (
    <span className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-full border-2 bg-panel-raised font-mono text-[10px] font-bold tracking-wide text-ink transition-all duration-200 ${ringByState[state]}`}>
      {kind}
    </span>
  )
  const text = (
    <span className={`flex min-w-0 flex-col font-mono ${side === 'src' ? 'items-end text-right' : 'items-start text-left'}`}>
      {namespace && <span className="max-w-full truncate text-[10px] leading-tight text-ink-dim">{namespace}</span>}
      <span className={`line-clamp-2 max-w-full break-all text-xs leading-tight font-semibold ${state === 'selected' ? 'text-signal' : 'text-ink'}`}>{truncateWorkloadName(workload)}</span>
    </span>
  )
  return (
    <>
      <Handle type="target" position={Position.Left} className="!border-0 !bg-transparent" />
      <div title={label} className={`flex w-[240px] items-center gap-3 transition-opacity duration-200 ${side === 'src' ? 'justify-end' : 'justify-start'} ${state === 'dimmed' ? 'opacity-20 grayscale' : ''}`}>
        {side === 'src' ? <>{text}{circle}</> : <>{circle}{text}</>}
      </div>
      <Handle type="source" position={Position.Right} className="!border-0 !bg-transparent" />
    </>
  )
}

// What a link means, decided by each graph from its own data:
//   pass  — traffic reaches the destination (drawn end to end)
//   stop  — blocked at the policy gate (drawn up to the ✕ badge only)
export interface PathEdgeData {
  outcome: 'pass' | 'stop'
  color: string
  // Short symbol inside the badge before the port label: ✓ ✕ ! or none.
  gate?: string
  badgeClass: string
  label: string
  fullLabel?: string
  labelT: number
  isDimmed: boolean
  animate: boolean
  [key: string]: unknown
}

export type PathEdgeType = Edge<PathEdgeData, 'path'>

// Edges spanning many rows get more curvature so they sweep around the
// dense horizontal midline instead of cutting straight through it.
export function linkCurvature(sourceY: number, targetY: number, rowHeight: number): number {
  return Math.min(0.6, 0.15 + (Math.abs(targetY - sourceY) / rowHeight) * 0.08)
}

export function makePathEdge(rowHeight: number) {
  return function PathEdge({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps<PathEdgeType>) {
    if (!data) return null
    const curve = linkCurve(sourceX, sourceY, targetX, targetY, linkCurvature(sourceY, targetY, rowHeight))
    const [labelX, labelY] = pointAt(curve, data.labelT)
    const full = cubicPath(curve)
    const drawn = data.outcome === 'stop' ? cubicPath(splitAt(curve, data.labelT)[0]) : full
    const dimmedOpacity = data.isDimmed ? 0.08 : 1
    return (
      <>
        {/* The whole route, faint: a blocked link still shows where it was going. */}
        <BaseEdge id={id} path={full} style={{ stroke: data.color, strokeWidth: 2, opacity: data.isDimmed ? 0.04 : data.outcome === 'stop' ? 0.18 : 0.3, transition: 'opacity 0.2s ease' }} />
        <path
          d={drawn}
          fill="none"
          stroke={data.color}
          strokeWidth={data.isDimmed ? 1 : 2.5}
          strokeLinecap="round"
          className={data.animate && !data.isDimmed ? 'probe-flow' : undefined}
          style={{ opacity: dimmedOpacity, transition: 'opacity 0.2s ease', pointerEvents: 'none' }}
        />
        {data.label && (
          <EdgeLabelRenderer>
            <div
              title={data.fullLabel || data.label}
              style={{
                position: 'absolute',
                transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
                pointerEvents: data.isDimmed ? 'none' : 'all',
                opacity: data.isDimmed ? 0.05 : 1,
                transition: 'opacity 0.2s ease',
              }}
              className={`z-10 flex items-center gap-1.5 border bg-panel px-2 py-0.5 font-mono text-[11px] font-semibold tracking-tight shadow-xs select-none ${data.badgeClass}`}
            >
              {data.gate && <span aria-hidden="true" className="text-[12px] leading-none">{data.gate}</span>}
              {data.label}
            </div>
          </EdgeLabelRenderer>
        )}
      </>
    )
  }
}
