// The connectivity test's stages, as the server streams them from
// POST /api/probes/connection/stream (probes.go's probeStage* constants).
// The stepper only ever shows stages the server actually reported: nothing
// here advances on a timer, so a stalled test looks stalled.
export const PROBE_STAGES = [
  { id: 'authorize', label: 'Authorize' },
  { id: 'capture', label: 'Hubble capture' },
  { id: 'inject', label: 'Inject probe' },
  { id: 'run', label: 'Run probe' },
  { id: 'collect', label: 'Collect flows' },
  { id: 'simulate', label: 'Simulate candidate' },
] as const

export type ProbeStageId = (typeof PROBE_STAGES)[number]['id']
export type ProbeStageState = 'pending' | 'active' | 'done' | 'failed' | 'skipped'
export type ProbeRunState = 'running' | 'done' | 'failed'

export function isProbeStage(value: unknown): value is ProbeStageId {
  return PROBE_STAGES.some((stage) => stage.id === value)
}

// reached is every stage the server reported, in order. While running the
// last one is in progress; once finished, stages never reached were skipped
// (e.g. no candidate simulation after a failed capture), and a failure
// belongs to the stage that was in progress when it happened.
export function probeStageStates(reached: readonly ProbeStageId[], run: ProbeRunState): Record<ProbeStageId, ProbeStageState> {
  const last = reached[reached.length - 1]
  const states = {} as Record<ProbeStageId, ProbeStageState>
  for (const { id } of PROBE_STAGES) {
    if (!reached.includes(id)) states[id] = run === 'running' ? 'pending' : 'skipped'
    else if (id !== last) states[id] = 'done'
    else states[id] = run === 'running' ? 'active' : run === 'failed' ? 'failed' : 'done'
  }
  return states
}

// splitNDJSON parses the complete lines of a newline-delimited JSON buffer
// and hands back the trailing partial line for the next chunk. A line that
// is not JSON is a protocol error, never silently skipped.
export function splitNDJSON(buffer: string): { lines: unknown[]; rest: string } {
  const parts = buffer.split('\n')
  const rest = parts.pop() ?? ''
  return { lines: parts.filter((line) => line.trim() !== '').map((line) => JSON.parse(line) as unknown), rest }
}
