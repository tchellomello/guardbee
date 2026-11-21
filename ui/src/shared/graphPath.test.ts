import { describe, expect, it } from 'vitest'
import { cubicPath, endpointKind, linkCurve, pointAt, splitAt } from './graphPath'

describe('link geometry', () => {
  const curve = linkCurve(0, 0, 400, 120, 0.3)

  it('starts and ends on the endpoints with horizontal tangents', () => {
    expect(pointAt(curve, 0)).toEqual([0, 0])
    expect(pointAt(curve, 1)).toEqual([400, 120])
    expect(curve[1][1]).toBe(0)
    expect(curve[2][1]).toBe(120)
  })

  it('splits exactly at the gate: the first part ends where the badge sits', () => {
    for (const t of [0.34, 0.5, 0.66]) {
      const [head, tail] = splitAt(curve, t)
      const gate = pointAt(curve, t)
      expect(head[3][0]).toBeCloseTo(gate[0])
      expect(head[3][1]).toBeCloseTo(gate[1])
      expect(tail[0]).toEqual(head[3])
      // A point halfway along the head is the original curve at t/2.
      const half = pointAt(head, 0.5)
      const original = pointAt(curve, t / 2)
      expect(half[0]).toBeCloseTo(original[0])
      expect(half[1]).toBeCloseTo(original[1])
    }
  })

  it('serializes as one SVG cubic command', () => {
    expect(cubicPath(linkCurve(0, 0, 10, 0, 0.5))).toBe('M0,0 C5,0 5,0 10,0')
  })
})

describe('endpointKind', () => {
  it.each([
    ['postgres/postgres-0', 'POD'],
    ['reserved:world', 'WORLD'],
    ['reserved:world-ipv4', 'WORLD'],
    ['reserved:host', 'HOST'],
    ['reserved:kube-apiserver', 'API'],
    ['reserved:remote-node', 'NODE'],
    ['reserved:health', 'PEER'],
    ['10.0.0.5', 'IP'],
    ['10.0.0.0/8', 'IP'],
    ['2001:db8::1', 'IP'],
    ['coredns', 'PEER'],
  ])('%s → %s', (label, kind) => {
    expect(endpointKind(label)).toBe(kind)
  })
})
