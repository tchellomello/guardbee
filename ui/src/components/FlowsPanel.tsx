import { useState } from 'react'
import { fetchFlows, type FlowsResponse } from '../api'
import { CheckRow, Field, NamespaceScope } from './NamespaceScope'
import { FlowsGraph } from './FlowsGraph'

// Matches the CLI's own flowVerdictColor (colors.go): green for FORWARDED,
// red for DROPPED, amber for AUDIT.
const VERDICT_STYLES: Record<string, string> = {
  FORWARDED: 'border-unchanged/40 bg-unchanged/10 text-unchanged',
  DROPPED: 'border-drop/40 bg-drop/10 text-drop',
  AUDIT: 'border-allow/40 bg-allow/10 text-allow',
}

export interface FlowsRunItem {
  id: string
  timestamp: Date
  namespace: string
  allNamespaces: boolean
  last: number
  result: FlowsResponse
  isCollapsed?: boolean
}

export function FlowsPanel() {
  const [namespace, setNamespace] = useState('')
  const [allNamespaces, setAllNamespaces] = useState(false)
  const [last, setLast] = useState(20)
  const [stackRuns, setStackRuns] = useState(false)

  const [runs, setRuns] = useState<FlowsRunItem[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    const runId = crypto.randomUUID()
    const ns = allNamespaces ? '' : namespace

    try {
      const res = await fetchFlows(ns, last)
      const newRun: FlowsRunItem = {
        id: runId,
        timestamp: new Date(),
        namespace: ns,
        allNamespaces,
        last,
        result: res,
      }
      setRuns((prev) => (stackRuns ? [newRun, ...prev] : [newRun]))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  function handleResetSession() {
    setRuns([])
    setError(null)
    setNamespace('')
    setAllNamespaces(false)
    setLast(20)
  }

  function handleClearResults() {
    setRuns([])
    setError(null)
  }

  function handleDuplicateToForm(run: FlowsRunItem) {
    setNamespace(run.namespace)
    setAllNamespaces(run.allNamespaces)
    setLast(run.last)
    setStackRuns(true)
  }

  function handleRemoveRun(id: string) {
    setRuns((prev) => prev.filter((r) => r.id !== id))
  }

  function handleToggleCollapse(id: string) {
    setRuns((prev) =>
      prev.map((r) => (r.id === id ? { ...r, isCollapsed: !r.isCollapsed } : r))
    )
  }

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleSubmit}
        className="rise-in flex flex-wrap items-end gap-5 border border-line bg-panel p-5"
      >
        <div className="w-64">
          <NamespaceScope
            namespace={namespace}
            onNamespaceChange={setNamespace}
            allNamespaces={allNamespaces}
            onAllNamespacesChange={setAllNamespaces}
          />
        </div>
        <div className="w-28">
          <Field label="Last">
            <input
              type="number"
              min={1}
              value={last}
              onChange={(e) => setLast(Number(e.target.value) || 1)}
              className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
            />
          </Field>
        </div>
        <div className="flex items-center pb-2.5">
          <CheckRow
            label="Stack runs (keep previous flows)"
            checked={stackRuns}
            onChange={setStackRuns}
          />
        </div>
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={loading}
            className="bg-signal px-5 py-2 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
          >
            {loading ? 'Fetching…' : 'Fetch flows'}
          </button>
          <button
            type="button"
            onClick={handleResetSession}
            disabled={loading}
            className="border border-line bg-void px-4 py-2 font-display text-xs font-bold tracking-[0.1em] text-ink-dim uppercase transition-colors hover:border-drop hover:text-drop disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
          >
            Reset
          </button>
        </div>
      </form>

      {error && <p className="rise-in border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">{error}</p>}

      {runs.length > 0 && (
        <div className="flex items-center justify-between border-b border-line pb-3">
          <span className="font-display text-xs font-bold uppercase tracking-wider text-ink">
            {runs.length === 1 ? 'Flows Result' : `Stacked Flows (${runs.length})`}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleClearResults}
              className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-drop transition-colors cursor-pointer"
            >
              Clear all flows
            </button>
          </div>
        </div>
      )}

      {runs.length === 0 && !loading && (
        <div className="border border-line bg-panel p-8 text-center text-ink-dim space-y-3">
          <p className="font-display text-xs uppercase tracking-wider text-ink">Ready to inspect flows</p>
          <p className="text-xs max-w-md mx-auto leading-relaxed">
            Pick a namespace scope, set how many recent flows to sample, and click <strong className="text-signal">Fetch flows</strong> to observe live Hubble traffic.
          </p>
        </div>
      )}

      {runs.map((run, index) => (
        <FlowRunCard
          key={run.id}
          run={run}
          runNumber={runs.length - index}
          onDuplicate={handleDuplicateToForm}
          onRemove={handleRemoveRun}
          onToggleCollapse={handleToggleCollapse}
        />
      ))}
    </div>
  )
}

function FlowRunCard({
  run,
  runNumber,
  onDuplicate,
  onRemove,
  onToggleCollapse,
}: {
  run: FlowsRunItem
  runNumber: number
  onDuplicate: (run: FlowsRunItem) => void
  onRemove: (id: string) => void
  onToggleCollapse: (id: string) => void
}) {
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null)

  const { result } = run
  const flows = result.flows

  // Compute breakdown counts
  const counts = flows.reduce<Record<string, number>>((acc, f) => {
    const v = f.verdict || 'FORWARDED'
    acc[v] = (acc[v] || 0) + 1
    return acc
  }, {})

  return (
    <div className="border border-line bg-panel p-5 space-y-5 rise-in">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="font-display text-xs font-bold text-signal">
            Run #{runNumber}
          </span>
          <span className="text-[0.7rem] font-mono text-ink-faint">
            {run.timestamp.toLocaleTimeString()}
          </span>
          <span className="border border-line bg-panel-raised px-2 py-0.5 font-mono text-[0.7rem] text-ink">
            {run.namespace ? `namespace: ${run.namespace}` : 'all namespaces'}
          </span>
          <span className="border border-line bg-panel-raised px-2 py-0.5 font-mono text-[0.7rem] text-ink-dim">
            last: {run.last}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onDuplicate(run)}
            title="Load this run's parameters back into the form"
            className="border border-line bg-void/60 px-2 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:border-signal hover:text-signal transition-colors cursor-pointer"
          >
            Duplicate to form
          </button>
          <button
            type="button"
            onClick={() => onToggleCollapse(run.id)}
            className="border border-line bg-void/60 px-2 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-ink transition-colors cursor-pointer"
          >
            {run.isCollapsed ? 'Expand' : 'Collapse'}
          </button>
          <button
            type="button"
            onClick={() => onRemove(run.id)}
            title="Remove this run"
            className="border border-line bg-void/60 px-2 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:border-drop hover:text-drop transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>
      </div>

      {!run.isCollapsed && (
        <div className="space-y-5">
          <p className="text-xs text-ink-dim">
            <span className="font-semibold text-ink">{flows.length}</span> flow(s) for{' '}
            <span className="text-ink">{result.namespace || 'all namespaces'}</span>
          </p>

          <div className="flex flex-wrap items-center gap-2">
            {counts['FORWARDED'] !== undefined && (
              <span className={`border px-2.5 py-1 text-xs font-medium ${VERDICT_STYLES.FORWARDED}`}>
                <span className="font-semibold">{counts['FORWARDED']}</span> forwarded
              </span>
            )}
            {counts['DROPPED'] !== undefined && (
              <span className={`border px-2.5 py-1 text-xs font-medium ${VERDICT_STYLES.DROPPED}`}>
                <span className="font-semibold">{counts['DROPPED']}</span> dropped
              </span>
            )}
            {counts['AUDIT'] !== undefined && (
              <span className={`border px-2.5 py-1 text-xs font-medium ${VERDICT_STYLES.AUDIT}`}>
                <span className="font-semibold">{counts['AUDIT']}</span> audit
              </span>
            )}
            {Object.entries(counts)
              .filter(([v]) => !['FORWARDED', 'DROPPED', 'AUDIT'].includes(v))
              .map(([v, count]) => (
                <span key={v} className="border border-line-bright bg-panel-raised px-2.5 py-1 text-xs font-medium text-ink-dim">
                  <span className="font-semibold">{count}</span> {v.toLowerCase()}
                </span>
              ))}
          </div>

          {counts['DROPPED'] ? (
            <p className="border border-drop/40 bg-drop/10 px-4 py-3 text-sm font-semibold text-drop">
              {counts['DROPPED']} dropped flow(s) observed in this sample!
            </p>
          ) : null}

          {/* Interactive Flow Graph */}
          {flows.length > 0 && (
            <FlowsGraph
              flows={flows}
              selectedNodeId={selectedGraphNode}
              onSelectNode={setSelectedGraphNode}
            />
          )}

          {flows.length === 0 && (
            <p className="text-sm text-ink-dim">
              No flows observed for this scope in Hubble's current buffer.
            </p>
          )}

          {flows.length > 0 && (
            <div className="overflow-x-auto border border-line">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="border-b border-line bg-panel-raised">
                  <tr>
                    {['Time', 'Verdict', 'Source', 'Destination', 'L4'].map((h) => (
                      <th key={h} className="px-3 py-2 text-[0.65rem] font-semibold tracking-[0.1em] text-ink-dim uppercase">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {flows.map((f, i) => {
                    const srcId = `src:${f.source}`
                    const dstId = `dst:${f.destination}`
                    return (
                    <tr key={i} className="hover:bg-panel-raised/60">
                      <td className="px-3 py-2 font-mono text-xs text-ink-faint">
                        {new Date(f.time).toLocaleTimeString()}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`border px-2 py-0.5 text-[0.65rem] font-semibold ${
                            VERDICT_STYLES[f.verdict] ?? 'border-line-bright bg-panel-raised text-ink-dim'
                          }`}
                        >
                          {f.verdict}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">
                        <GraphNodeLink
                          selected={selectedGraphNode === srcId}
                          onClick={() => setSelectedGraphNode((prev) => (prev === srcId ? null : srcId))}
                        >
                          {f.source}
                        </GraphNodeLink>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">
                        <GraphNodeLink
                          selected={selectedGraphNode === dstId}
                          onClick={() => setSelectedGraphNode((prev) => (prev === dstId ? null : dstId))}
                        >
                          {f.destination}
                        </GraphNodeLink>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">{f.l4}</td>
                    </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// Makes a table cell's source/destination text clickable, selecting the
// matching node in the FlowsGraph above — the same isolation effect as
// clicking the box directly, triggered from the row instead.
function GraphNodeLink({
  selected,
  onClick,
  children,
}: {
  selected: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Select this node in the flow graph above"
      className={`cursor-pointer text-left underline decoration-dotted underline-offset-2 transition-colors hover:text-signal ${
        selected ? 'text-signal font-semibold' : ''
      }`}
    >
      {children}
    </button>
  )
}
