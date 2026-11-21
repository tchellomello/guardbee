import { describe, expect, it } from 'vitest'
import { isProbeStage, probeStageStates, splitNDJSON } from './probeStages'

describe('probeStageStates', () => {
  it('marks the latest reported stage active while running, never ahead of the server', () => {
    expect(probeStageStates(['authorize', 'capture'], 'running')).toEqual({
      authorize: 'done', capture: 'active', inject: 'pending', run: 'pending', collect: 'pending', simulate: 'pending',
    })
    expect(Object.values(probeStageStates([], 'running')).every((state) => state === 'pending')).toBe(true)
  })

  it('blames the in-progress stage for a failure and skips the rest', () => {
    expect(probeStageStates(['authorize', 'capture', 'inject'], 'failed')).toEqual({
      authorize: 'done', capture: 'done', inject: 'failed', run: 'skipped', collect: 'skipped', simulate: 'skipped',
    })
  })

  it('shows an unreached simulation as skipped, not done, when the test finished', () => {
    const states = probeStageStates(['authorize', 'capture', 'inject', 'run', 'collect'], 'done')
    expect(states.collect).toBe('done')
    expect(states.simulate).toBe('skipped')
  })
})

describe('splitNDJSON', () => {
  it('keeps a partial trailing line for the next chunk', () => {
    expect(splitNDJSON('{"stage":"authorize"}\n{"stage":"capt')).toEqual({ lines: [{ stage: 'authorize' }], rest: '{"stage":"capt' })
    expect(splitNDJSON('\n{"result":{}}\n')).toEqual({ lines: [{ result: {} }], rest: '' })
  })

  it('throws on a corrupt line instead of dropping it', () => {
    expect(() => splitNDJSON('not json\n')).toThrow()
  })

  it('only accepts known stage ids', () => {
    expect(isProbeStage('inject')).toBe(true)
    expect(isProbeStage('exec')).toBe(false)
  })
})
