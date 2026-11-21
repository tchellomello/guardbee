import { shortenMiddle, type ConnectivityDecision } from '../shared/connectivity'

// The test drawn as the path it took: source Pod on the left, destination on
// the right, and one lane per policy model through the policy gate in the
// middle. An allowed lane carries moving traffic end to end; a blocked one
// stops at the gate; an inconclusive one is a dashed outline with a "?".
// The SVG is decoration for sighted users — the decisions are also spelled
// out as text next to it (and in the aria-label), which is what assistive
// tech and the e2e specs read.
export function ProbePath({ source, destination, l4, baseline, candidate }: {
  source: string; destination: string; l4: string; baseline: ConnectivityDecision; candidate: ConnectivityDecision
}) {
  return (
    <svg role="img" aria-label={`${source} to ${destination}: baseline ${baseline.toLowerCase()}, candidate ${candidate.toLowerCase()}`} viewBox="-12 0 624 204" className="block h-auto w-full max-w-2xl">
      <Lane y={62} label="BASELINE" decision={baseline} />
      <Lane y={138} label="CANDIDATE" decision={candidate} />
      <Gate />
      <Endpoint x={66} kind="POD" name={source} />
      <Endpoint x={534} kind={l4} name={destination} />
    </svg>
  )
}

const tone: Record<ConnectivityDecision, string> = { ALLOWED: 'text-signal', BLOCKED: 'text-drop', INCONCLUSIVE: 'text-ink-faint' }

function Lane({ y, label, decision }: { y: number; label: string; decision: ConnectivityDecision }) {
  const full = `M94 100 C150 100 150 ${y} 200 ${y} L400 ${y} C450 ${y} 450 100 506 100`
  const toGate = `M94 100 C150 100 150 ${y} 200 ${y} L286 ${y}`
  return (
    <g className={tone[decision]}>
      <path d={full} fill="none" stroke="currentColor" strokeOpacity={decision === 'ALLOWED' ? 0.25 : 0.18} strokeWidth={decision === 'INCONCLUSIVE' ? 1.5 : 3} strokeDasharray={decision === 'INCONCLUSIVE' ? '4 6' : undefined} />
      {decision === 'ALLOWED' && <path d={full} fill="none" stroke="currentColor" strokeWidth={3} strokeLinecap="round" className="probe-flow" />}
      {decision === 'BLOCKED' && <path d={toGate} fill="none" stroke="currentColor" strokeWidth={3} strokeLinecap="round" />}
      <text x={206} y={y - 10} fill="currentColor" fontSize={10} fontFamily="ui-monospace, monospace" letterSpacing={1.5}>{label}</text>
      <circle cx={300} cy={y} r={13} fill="var(--color-panel)" stroke="currentColor" strokeWidth={2} />
      <text x={300} y={y + 4.5} fill="currentColor" fontSize={13} fontWeight={700} textAnchor="middle" fontFamily="ui-monospace, monospace">
        {decision === 'ALLOWED' ? '✓' : decision === 'BLOCKED' ? '✕' : '?'}
      </text>
    </g>
  )
}

// The policy gate both lanes cross: a shield outline behind the markers.
function Gate() {
  return (
    <g className="text-line-bright" aria-hidden="true">
      <path d="M300 22 L340 36 L340 110 Q340 160 300 182 Q260 160 260 110 L260 36 Z" fill="none" stroke="currentColor" strokeWidth={1.5} strokeDasharray="2 4" />
      <text x={300} y={196} fill="currentColor" fontSize={9} textAnchor="middle" fontFamily="ui-monospace, monospace" letterSpacing={1.5}>POLICY</text>
    </g>
  )
}

function Endpoint({ x, kind, name }: { x: number; kind: string; name: string }) {
  return (
    <g>
      <title>{name}</title>
      <circle cx={x} cy={100} r={28} fill="var(--color-panel-raised)" stroke="var(--color-line-bright)" strokeWidth={1.5} />
      <text x={x} y={104} fill="var(--color-ink)" fontSize={kind.length > 4 ? 9 : 11} fontWeight={700} textAnchor="middle" fontFamily="ui-monospace, monospace">{kind}</text>
      <text x={x} y={146} fill="var(--color-ink-dim)" fontSize={10} textAnchor="middle" fontFamily="ui-monospace, monospace">{shortenMiddle(name)}</text>
    </g>
  )
}
