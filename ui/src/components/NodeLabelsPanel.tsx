// Shown below VerdictGraph/FlowsGraph when a node is selected — looks up
// the real pod behind a "namespace/pod-name" node (if any) and shows its
// live, non-volatile labels, so users can see *why* a flow matched without
// leaving the graph.

import { nonVolatileLabels, parseNamespacePod, useNamespacePods } from '../shared/podLabels'

export function NodeLabelsPanel({ nodeName }: { nodeName: string }) {
  const parsed = parseNamespacePod(nodeName)
  const { byNamespace, loading } = useNamespacePods(parsed ? [parsed.namespace] : [])

  if (!parsed) {
    return (
      <div className="mb-2 border border-line bg-panel-raised/40 px-3 py-2 text-xs text-ink-faint italic rise-in">
        {nodeName} is a reserved identity or external address — no pod labels to show.
      </div>
    )
  }

  const pods = byNamespace[parsed.namespace]
  const pod = pods?.find((p) => p.name === parsed.podName)
  const labels = pod ? nonVolatileLabels(pod.labels) : []

  return (
    <div className="mb-2 border border-line bg-panel-raised/40 px-3 py-2 rise-in">
      <div className="mb-1.5 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
        Pod labels — {parsed.namespace}
      </div>
      {pods === undefined && loading && (
        <p className="text-xs text-ink-dim">Looking up pod in {parsed.namespace}…</p>
      )}
      {pods !== undefined && !pod && (
        <p className="text-xs text-ink-faint italic">
          Pod no longer present in {parsed.namespace} — may have been replaced or scaled down since this flow.
        </p>
      )}
      {pod && labels.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {labels.map(([k, v]) => (
            <span
              key={k}
              className="border border-signal/30 bg-signal/5 px-1.5 py-0.5 text-[0.65rem] font-mono text-signal"
            >
              {k}={v}
            </span>
          ))}
        </div>
      )}
      {pod && labels.length === 0 && (
        <p className="text-xs text-ink-faint italic">No non-volatile labels on this pod.</p>
      )}
    </div>
  )
}
