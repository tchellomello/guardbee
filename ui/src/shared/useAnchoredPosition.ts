// Computes viewport-relative coordinates for a dropdown anchored to a
// trigger element, so the dropdown can use `position: fixed` instead of
// `absolute`. `absolute` dropdowns get silently clipped by any scrollable
// ancestor whose content they'd overflow (e.g. a modal with
// overflow-y-auto) — `fixed`, positioned from the trigger's real screen
// rect, escapes that entirely as long as no ancestor sets a transform
// (none in this app do; see the .rise-in fix in index.css).

import { useLayoutEffect, useState, type RefObject } from 'react'

export interface AnchoredPosition {
  top: number
  left: number
  right: number
}

export function useAnchoredPosition(
  triggerRef: RefObject<HTMLElement | null>,
  open: boolean
): AnchoredPosition | null {
  const [pos, setPos] = useState<AnchoredPosition | null>(null)

  useLayoutEffect(() => {
    if (!open || !triggerRef.current) {
      setPos(null)
      return
    }
    const rect = triggerRef.current.getBoundingClientRect()
    setPos({ top: rect.bottom + 4, left: rect.left, right: window.innerWidth - rect.right })
  }, [open, triggerRef])

  return pos
}
