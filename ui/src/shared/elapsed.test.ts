import { describe, expect, it } from 'vitest'
import { formatElapsed } from './elapsed'

describe('formatElapsed', () => {
  it('shows tenths of a second under a minute', () => {
    expect(formatElapsed(0)).toBe('0.0s')
    expect(formatElapsed(3240)).toBe('3.2s')
    expect(formatElapsed(59_940)).toBe('59.9s')
  })

  it('switches to minutes past a minute', () => {
    expect(formatElapsed(59_960)).toBe('1m0.0s')
    expect(formatElapsed(64_500)).toBe('1m4.5s')
  })
})
