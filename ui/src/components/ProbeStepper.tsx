import { PROBE_STAGES, probeStageStates, type ProbeRunState, type ProbeStageId, type ProbeStageState } from '../shared/probeStages'

// One row of nodes joined by a rail: the stages the server reported, as it
// reported them. Labels stay in the DOM on small screens (screen readers,
// tests) but only the active/failed one is shown under the rail there.
export function ProbeStepper({ reached, run }: { reached: readonly ProbeStageId[]; run: ProbeRunState }) {
  const states = probeStageStates(reached, run)
  return (
    <ol aria-label="Connection test progress" className="grid min-w-0 grid-cols-6 gap-0">
      {PROBE_STAGES.map((stage, i) => {
        const state = states[stage.id]
        const prevDone = i > 0 && states[PROBE_STAGES[i - 1].id] === 'done'
        return (
          <li key={stage.id} aria-current={state === 'active' ? 'step' : undefined} data-state={state} className="relative flex min-w-0 flex-col items-center gap-2 text-center">
            {i > 0 && <span aria-hidden="true" className={`absolute top-3 right-1/2 h-px w-full ${prevDone ? 'bg-signal' : 'bg-line'}`} />}
            <StageDot state={state} />
            <span className={`text-[0.65rem] leading-tight ${state === 'active' || state === 'failed' ? 'block' : 'hidden sm:block'} ${state === 'failed' ? 'text-drop' : state === 'active' ? 'text-ink' : state === 'done' ? 'text-ink-dim' : 'text-ink-faint'}`}>
              {stage.label}<span className="sr-only"> — {stateLabel[state]}</span>
            </span>
          </li>
        )
      })}
    </ol>
  )
}

const stateLabel: Record<ProbeStageState, string> = { pending: 'pending', active: 'in progress', done: 'done', failed: 'failed', skipped: 'skipped' }

function StageDot({ state }: { state: ProbeStageState }) {
  const base = 'relative z-10 flex h-6 w-6 items-center justify-center rounded-full border text-[0.7rem] font-bold'
  switch (state) {
    case 'done':
      return <span aria-hidden="true" className={`${base} border-signal bg-signal text-void`}>✓</span>
    case 'active':
      return <span aria-hidden="true" className={`${base} glow-pulse border-signal bg-panel text-signal`}>•</span>
    case 'failed':
      return <span aria-hidden="true" className={`${base} border-drop bg-drop text-void`}>✕</span>
    case 'skipped':
      return <span aria-hidden="true" className={`${base} border-dashed border-line bg-panel text-ink-faint`}>–</span>
    default:
      return <span aria-hidden="true" className={`${base} border-line bg-panel`} />
  }
}
