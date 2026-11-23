import { describe, expect, it } from 'vitest'
import type { EditablePolicyModel } from '../api'
import { editorRefusal } from './editorFit'

const policy = {} as EditablePolicyModel

describe('editorRefusal', () => {
  it('lets a single, representable policy through', () => {
    expect(editorRefusal({ valid: true, policy })).toBeNull()
  })
  it('passes the parse error on', () => {
    expect(editorRefusal({ valid: false, error: 'bad yaml' })).toBe('bad yaml')
    expect(editorRefusal({ valid: true })).toBe('Not a valid policy')
  })
  it('refuses several documents, saying how many', () => {
    expect(editorRefusal({ valid: true, policy, lossy: true, documents: 3 })).toContain('holds 3 policies')
  })
  it('refuses a policy the editor would lose rules from', () => {
    expect(editorRefusal({ valid: true, policy, lossy: true })).toContain('L7 HTTP/DNS rules')
  })
})
