import { describe, expect, it } from 'vitest'
import { duplicateLabelKeys, labelsToRows, parseCommaList, rowsToLabels, sameLabels } from './draftInputs'

describe('parseCommaList', () => {
  it('ignores the empty piece a trailing comma leaves mid-typing', () => {
    expect(parseCommaList('10.0.0.0/8, ')).toEqual(['10.0.0.0/8'])
    expect(parseCommaList('10.0.0.0/8, 192.168.1.0/24')).toEqual(['10.0.0.0/8', '192.168.1.0/24'])
    expect(parseCommaList('')).toEqual([])
  })
})

describe('label rows', () => {
  it('round-trips labels, keeping order', () => {
    const labels = { app: 'web', tier: 'front' }
    expect(rowsToLabels(labelsToRows(labels, 0))).toEqual(labels)
  })

  it('leaves out rows whose key is still empty', () => {
    expect(
      rowsToLabels([
        { id: 1, key: '', value: 'typed-first' },
        { id: 2, key: 'app', value: 'web' },
      ])
    ).toEqual({ app: 'web' })
  })

  it('keeps the first of two rows with the same key and reports the duplicate', () => {
    const rows = [
      { id: 1, key: 'app', value: 'my-service' },
      { id: 2, key: 'app', value: '' },
    ]
    expect(rowsToLabels(rows)).toEqual({ app: 'my-service' })
    expect([...duplicateLabelKeys(rows)]).toEqual(['app'])
  })

  it('keeps a digit-first key as an ordinary label', () => {
    const rows = [
      { id: 1, key: 'app', value: 'web' },
      { id: 2, key: '42x', value: 'y' },
    ]
    expect(rowsToLabels(rows)).toEqual({ app: 'web', '42x': 'y' })
  })

  it('compares label sets regardless of key order', () => {
    expect(sameLabels({ a: '1', b: '2' }, { b: '2', a: '1' })).toBe(true)
    expect(sameLabels({ a: '1' }, { a: '2' })).toBe(false)
  })
})
