import { useEffect, useState } from 'react'
import { fetchVersion, type VersionInfo } from '../api'

// Phase 1 UI counterpart to the CLI's stderr version-skew warning (see
// ../../clusterversion.go's warnOnVersionSkew) — persistent across every
// tab, not buried in one panel, since a version mismatch affects every
// verdict equally. Renders nothing for the common case: no skew, or
// detection came back unknown because hubble-relay wasn't reachable from
// here — the same "silent unless there's something to say" the CLI
// follows.
export function VersionBanner() {
  const [info, setInfo] = useState<VersionInfo | null>(null)

  useEffect(() => {
    fetchVersion()
      .then(setInfo)
      .catch(() => {
        // Best-effort, same as the CLI's warnOnVersionSkew — a failed
        // /api/version call just means no banner, not an error surfaced
        // to the user.
      })
  }, [])

  if (!info || info.unknown || (!info.skewed && !info.nodeSkew)) return null

  return (
    <div className="px-6 pt-4 lg:px-10">
      <div className="flex items-start gap-2 border border-allow/40 bg-allow/10 px-3 py-2 text-xs text-allow">
        <span>⚠</span>
        {info.nodeSkew ? (
          <span>
            Cluster nodes disagree on Cilium version ({info.nodeVersions?.join(', ')}) — likely a rolling upgrade in
            progress. This binary is pinned to <span className="font-semibold">{info.pinned}</span>; verdicts may
            not match every node's actual enforcement.
          </span>
        ) : (
          <span>
            Cluster is running Cilium <span className="font-semibold">{info.detected}</span>, this binary is
            pinned to <span className="font-semibold">{info.pinned}</span> — verdicts use the pinned version's
            policy engine semantics, which may not exactly match what the cluster actually enforces.
          </span>
        )}
      </div>
    </div>
  )
}
