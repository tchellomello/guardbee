import { useEffect, useState } from 'react'

// Same rounding as the CLI's formatElapsed (verdict.go): tenths of a
// second, minutes once a run (usually a live stream) passes one.
export function formatElapsed(ms: number): string {
  const tenths = Math.round(Math.max(0, ms) / 100)
  if (tenths < 600) return `${(tenths / 10).toFixed(1)}s`
  const minutes = Math.floor(tenths / 600)
  return `${minutes}m${((tenths % 600) / 10).toFixed(1)}s`
}

// Milliseconds since startMs, re-rendering while it's non-null so a running
// verdict shows a live clock; null stops the ticking.
export function useElapsedMs(startMs: number | null): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (startMs === null) return
    setNow(Date.now())
    const id = setInterval(() => setNow(Date.now()), 100)
    return () => clearInterval(id)
  }, [startMs])
  return startMs === null ? 0 : Math.max(0, now - startMs)
}
