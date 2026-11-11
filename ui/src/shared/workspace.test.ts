import { describe, expect, it } from 'vitest'
import {
  countDocuments,
  duplicateEntry,
  firstPolicyName,
  removeEntry,
  renameEntry,
  saveEntry,
  type NewSavedPolicy,
} from './workspace'

const entry = (name: string, yaml = 'kind: X\n'): NewSavedPolicy => ({
  name,
  origin: 'verdict',
  candidateYAML: yaml,
  namespace: 'alpha',
  allNamespaces: false,
})

describe('workspace list operations', () => {
  it('saves new entries on top and updates same-named ones in place', () => {
    let { list, updated } = saveEntry([], entry('a'))
    expect(updated).toBe(false)
    ;({ list } = saveEntry(list, entry('b')))
    const firstId = list[1].id
    ;({ list, updated } = saveEntry(list, entry(' a ', 'kind: Y\n')))
    expect(updated).toBe(true)
    expect(list.map((p) => p.name)).toEqual(['a', 'b'])
    expect(list[0].id).toBe(firstId)
    expect(list[0].candidateYAML).toBe('kind: Y\n')
  })

  it('renames, refusing blanks and collisions', () => {
    let { list } = saveEntry([], entry('a'))
    ;({ list } = saveEntry(list, entry('b')))
    const idA = list.find((p) => p.name === 'a')!.id
    expect(renameEntry(list, idA, 'b')).toBe(list)
    expect(renameEntry(list, idA, '  ')).toBe(list)
    expect(renameEntry(list, idA, 'c').find((p) => p.id === idA)!.name).toBe('c')
  })

  it('duplicates next to the source with a unique name, and removes', () => {
    const { list } = saveEntry([], entry('a'))
    const once = duplicateEntry(list, list[0].id)
    const twice = duplicateEntry(once, list[0].id)
    expect(twice.map((p) => p.name)).toEqual(['a', 'a (copy 2)', 'a (copy)'])
    expect(new Set(twice.map((p) => p.id)).size).toBe(3)
    expect(removeEntry(twice, list[0].id).map((p) => p.name)).toEqual(['a (copy 2)', 'a (copy)'])
  })
})

describe('YAML helpers', () => {
  const multi = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  namespace: alpha
  name: lock-egress
spec: {}
---
# comment only
---
metadata:
  name: guardbee-allow-x
`
  it('counts non-empty documents', () => {
    expect(countDocuments(multi)).toBe(2)
    expect(countDocuments('')).toBe(0)
  })

  it('finds the first metadata.name', () => {
    expect(firstPolicyName(multi)).toBe('lock-egress')
    expect(firstPolicyName('kind: X\n')).toBeNull()
  })
})
