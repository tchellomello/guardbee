// Geometry and classification behind the flow graphs' "path" look (the same
// visual language as the connectivity test's ProbePath): one cubic curve
// per link, which a blocked link draws only up to its policy gate, and a
// round endpoint node labelled by what kind of peer it is.

export type Point = [number, number]
export type Cubic = [Point, Point, Point, Point]

// The link's curve: horizontal tangents at both ends, bowed by curvature.
// Kept in one place so the drawn path, the gate badge and a blocked link's
// cut-off point all sit on the exact same curve.
export function linkCurve(sx: number, sy: number, tx: number, ty: number, curvature: number): Cubic {
  const dx = (tx - sx) * curvature
  return [[sx, sy], [sx + dx, sy], [tx - dx, ty], [tx, ty]]
}

export function pointAt([p0, p1, p2, p3]: Cubic, t: number): Point {
  const mt = 1 - t
  const a = mt * mt * mt, b = 3 * mt * mt * t, c = 3 * mt * t * t, d = t * t * t
  return [a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0], a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]]
}

const lerp = (p: Point, q: Point, t: number): Point => [p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t]

// De Casteljau split: the curve up to t and the rest, each an exact cubic,
// so a blocked link can stop precisely at its gate badge.
export function splitAt([p0, p1, p2, p3]: Cubic, t: number): [Cubic, Cubic] {
  const p01 = lerp(p0, p1, t), p12 = lerp(p1, p2, t), p23 = lerp(p2, p3, t)
  const p012 = lerp(p01, p12, t), p123 = lerp(p12, p23, t)
  const mid = lerp(p012, p123, t)
  return [[p0, p01, p012, mid], [mid, p123, p23, p3]]
}

export function cubicPath([p0, p1, p2, p3]: Cubic): string {
  return `M${p0[0]},${p0[1]} C${p1[0]},${p1[1]} ${p2[0]},${p2[1]} ${p3[0]},${p3[1]}`
}

export type EndpointKind = 'POD' | 'WORLD' | 'HOST' | 'API' | 'NODE' | 'IP' | 'PEER'

// What the round node says inside it. Labels are the graphs' own peer
// strings: "ns/pod", "reserved:world", an IP or CIDR, or a bare name.
export function endpointKind(label: string): EndpointKind {
  if (label.startsWith('reserved:')) {
    const what = label.slice('reserved:'.length)
    if (what.startsWith('world')) return 'WORLD'
    if (what === 'host') return 'HOST'
    if (what === 'kube-apiserver') return 'API'
    if (what === 'remote-node') return 'NODE'
    return 'PEER'
  }
  if (/^[0-9a-f.:]+(\/\d{1,3})?$/i.test(label) && /[.:]/.test(label)) return 'IP'
  if (label.includes('/')) return 'POD'
  return 'PEER'
}
