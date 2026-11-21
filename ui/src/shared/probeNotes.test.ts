import { describe, expect, it } from 'vitest'
import { noteDisplay, warningDisplay } from './probeNotes'

describe('noteDisplay', () => {
  it('titles a known code without reading its sentence', () => {
    expect(noteDisplay({ code: 'ephemeral-entry', text: 'anything at all' })).toEqual({ icon: '⧉', title: 'Ephemeral entry stays until Pod replacement' })
  })

  it('still shows an unknown code, titled by its first clause', () => {
    expect(noteDisplay({ code: 'future-thing', text: 'Something new happened. More detail here.' })).toEqual({ icon: 'ℹ', title: 'Something new happened' })
    expect(noteDisplay({ code: 'x', text: 'y'.repeat(100) }).title).toHaveLength(58)
  })
})

describe('warningDisplay', () => {
  it('uses the lead-in before the first colon as the title', () => {
    expect(warningDisplay('Simulation inconclusive: NetworkPolicy objects in namespace db are not modeled')).toEqual({
      title: 'Simulation inconclusive', detail: 'NetworkPolicy objects in namespace db are not modeled',
    })
  })

  it('falls back to the first clause when there is no short lead-in', () => {
    const w = warningDisplay('No correlated Hubble flows observed; no policy conclusion is available')
    expect(w.title).toBe('No correlated Hubble flows observed')
    expect(w.detail).toContain('no policy conclusion')
  })
})
