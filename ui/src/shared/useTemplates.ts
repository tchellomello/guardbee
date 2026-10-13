// Fetches the Policy Editor's preset templates once on mount (see
// ../../../templates.go and api.ts's fetchTemplates) — the directory-backed
// replacement for the old hardcoded PRESET_TEMPLATES/INGRESS_RULE_PRESETS/
// EGRESS_RULE_PRESETS arrays in policy.ts. Consumers should treat an
// in-flight or failed fetch as "no presets yet" rather than an error state:
// policy.ts's BLANK_POLICY is always available locally regardless, so the
// editor is never left with nothing to start from.

import { useEffect, useState } from 'react'
import { fetchTemplates, type TemplatesResponse } from '../api'

const EMPTY: TemplatesResponse = { generic: [], ingress: [], egress: [] }

export function useTemplates() {
  const [templates, setTemplates] = useState<TemplatesResponse>(EMPTY)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchTemplates()
      .then((res) => {
        if (cancelled) return
        setTemplates(res)
        setLoading(false)
      })
      .catch((err) => {
        if (cancelled) return
        setError(err instanceof Error ? err.message : String(err))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return { templates, loading, error }
}
