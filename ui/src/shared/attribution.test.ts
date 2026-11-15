import { describe, expect, it } from 'vitest'
import type { Flow, PolicyRef } from '../api'
import { attributionBadges, isEditablePolicyRef } from './attribution'

const ref = (over: Partial<PolicyRef>): PolicyRef => ({ kind: 'CiliumNetworkPolicy', namespace: 'app', name: 'web', display: 'CNP:app/web', ...over })
const flow = (over: Partial<Flow>): Flow => ({ time: '', verdict: 'FORWARDED', source: 'a', destination: 'b', l4: 'TCP:80', ...over })

describe('isEditablePolicyRef', () => {
  it('opens only named CNPs and CCNPs', () => {
    expect(isEditablePolicyRef(ref({}))).toBe(true)
    expect(isEditablePolicyRef(ref({ kind: 'CiliumClusterwideNetworkPolicy', namespace: undefined }))).toBe(true)
    expect(isEditablePolicyRef(ref({ kind: 'NetworkPolicy' }))).toBe(false)
    expect(isEditablePolicyRef(ref({ kind: undefined }))).toBe(false)
    expect(isEditablePolicyRef(ref({ name: undefined }))).toBe(false)
  })
})

describe('attributionBadges', () => {
  it('shows allowedBy for an allow and deniedBy for a deny or audit', () => {
    expect(attributionBadges(flow({ decision: 'allowed', allowedBy: [ref({})], deniedBy: [ref({ name: 'x' })] }))).toEqual({ lead: 'allowed by', refs: [ref({})] })
    expect(attributionBadges(flow({ decision: 'denied', deniedBy: [ref({})] }))?.lead).toBe('denied by')
    expect(attributionBadges(flow({ decision: 'audit', deniedBy: [ref({})] }))?.lead).toBe('audit: would be denied by')
  })

  it('has no badges without attributed policies or a decision', () => {
    expect(attributionBadges(flow({ decision: 'default-deny' }))).toBeNull()
    expect(attributionBadges(flow({ decision: 'allowed', deniedBy: [ref({})] }))).toBeNull()
    expect(attributionBadges(flow({}))).toBeNull()
  })
})
