import { useEffect, useRef, useState } from 'react'
import { fetchPods, runVerdict, type VerdictChange, type VerdictResponse, type VerdictRow } from '../api'
import { classifyTrafficPeer } from './RuleEditorCard'
import { CheckRow, Field, NamespaceScope } from './NamespaceScope'
import { PolicyTextModal } from './PolicyTextModal'
import { VerdictGraph } from './VerdictGraph'
import { VerdictHelpModal } from './VerdictHelpModal'
import { parseNamespacePod } from '../shared/podLabels'
import type { EgressRule, IngressRule, Protocol } from '../policy'

// Visual language matches the CLI's own colorize/changeColor (colors.go):
// red for NEWLY_DROPPED, amber for NEWLY_ALLOWED, green for UNCHANGED —
// same categories, same meaning, just rendered as chips instead of ANSI.
const CHANGE_STYLES: Record<VerdictChange, string> = {
  NEWLY_DROPPED: 'border-drop/40 bg-drop/10 text-drop',
  NEWLY_ALLOWED: 'border-allow/40 bg-allow/10 text-allow',
  UNCHANGED: 'border-unchanged/40 bg-unchanged/10 text-unchanged',
}

// Filled variants, reserved for the newly-dropped/newly-allowed summary
// chips only — those are the actual answer this tool exists to give, so
// they get the same solid-fill treatment as the primary "Run verdict"
// button instead of the muted border+low-opacity look every other chip uses.
const HEADLINE_CHIP_STYLES: Record<'NEWLY_DROPPED' | 'NEWLY_ALLOWED', string> = {
  NEWLY_DROPPED: 'border-drop bg-drop text-void font-bold',
  NEWLY_ALLOWED: 'border-allow bg-allow text-void font-bold',
}

const CATEGORY_ORDER: VerdictChange[] = ['NEWLY_DROPPED', 'NEWLY_ALLOWED', 'UNCHANGED']

// Mirrors the results table's own columns/order exactly, so what gets
// pasted into a PR description or ticket matches what's on screen.
function rowsToMarkdownTable(rows: VerdictRow[]): string {
  const escapeCell = (v: string) => v.replace(/\|/g, '\\|')
  const header = '| Change | Source | Destination | Port | Seen | Why |\n| --- | --- | --- | --- | --- | --- |'
  const lines = rows.map(
    (r) =>
      `| ${r.change} | ${escapeCell(r.source)} | ${escapeCell(r.destination)} | ${r.protocol}:${r.port} | ${
        r.count > 1 ? `${r.count}×` : '—'
      } | ${escapeCell(r.explanation)} |`
  )
  return [header, ...lines].join('\n')
}

const EMPTY_COUNTS = {
  unchanged: 0,
  newlyDropped: 0,
  newlyAllowed: 0,
  notSimulated: 0,
  replySkipped: 0,
  total: 0,
}

export interface VerdictRunItem {
  id: string
  timestamp: Date
  namespace: string
  allNamespaces: boolean
  last: number
  showUnchanged: boolean
  candidateYAML: string
  isStreaming: boolean
  result: VerdictResponse
  isCollapsed?: boolean
}

export interface VerdictPanelProps {
  initialNamespace?: string
  initialCandidateYAML?: string
  // The Policy Editor's in-progress draft namespace and a way to append a
  // rule to it — lets a NEWLY_DROPPED/NEWLY_ALLOWED row be turned straight
  // into a rule on that draft without retyping anything, then jumps to the
  // Policy Editor with the new rule selected for review.
  policyNamespace?: string
  onAppendRuleToPolicy?: (direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) => void
}

export function VerdictPanel({
  initialNamespace,
  initialCandidateYAML,
  policyNamespace = '',
  onAppendRuleToPolicy,
}: VerdictPanelProps = {}) {
  const [namespace, setNamespace] = useState(initialNamespace || '')
  const [allNamespaces, setAllNamespaces] = useState(false)
  const [last, setLast] = useState(50)
  const [showUnchanged, setShowUnchanged] = useState(false)
  const [follow, setFollow] = useState(false)
  const [candidateYAML, setCandidateYAML] = useState(initialCandidateYAML || '')
  const [stackRuns, setStackRuns] = useState(false)

  const [runs, setRuns] = useState<VerdictRunItem[]>([])
  const [loading, setLoading] = useState(false)
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Help modal state
  const [helpOpen, setHelpOpen] = useState(false)
  const [helpCategory, setHelpCategory] = useState<string | null>(null)
  const [expandedEditorOpen, setExpandedEditorOpen] = useState(false)

  const eventSourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (initialNamespace !== undefined) setNamespace(initialNamespace)
  }, [initialNamespace])

  useEffect(() => {
    if (initialCandidateYAML !== undefined) setCandidateYAML(initialCandidateYAML)
  }, [initialCandidateYAML])

  useEffect(() => () => eventSourceRef.current?.close(), [])

  function openHelp(category?: string) {
    setHelpCategory(category || null)
    setHelpOpen(true)
  }

  function stopStreaming() {
    eventSourceRef.current?.close()
    eventSourceRef.current = null
    setStreaming(false)
  }

  function handleResetSession() {
    stopStreaming()
    setRuns([])
    setError(null)
    setNamespace('')
    setAllNamespaces(false)
    setLast(50)
    setShowUnchanged(false)
    setFollow(false)
    setCandidateYAML('')
  }

  function handleClearResults() {
    stopStreaming()
    setRuns([])
    setError(null)
  }

  function handleDuplicateToForm(run: VerdictRunItem) {
    setNamespace(run.namespace)
    setAllNamespaces(run.allNamespaces)
    setLast(run.last)
    setShowUnchanged(run.showUnchanged)
    setCandidateYAML(run.candidateYAML)
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

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    stopStreaming()
    setError(null)

    const ns = allNamespaces ? '' : namespace
    const runId = `run-${Date.now()}`

    if (follow) {
      setStreaming(true)
      const initialRun: VerdictRunItem = {
        id: runId,
        timestamp: new Date(),
        namespace: ns,
        allNamespaces,
        last,
        showUnchanged,
        candidateYAML,
        isStreaming: true,
        result: {
          namespace: ns,
          candidateRuleCount: 0,
          baselineRuleCount: 0,
          flowsRequested: last,
          flowsSampled: 0,
          counts: EMPTY_COUNTS,
          rows: [],
        },
      }

      setRuns((prev) => (stackRuns ? [initialRun, ...prev] : [initialRun]))

      const params = new URLSearchParams({
        candidateYAML,
        last: String(last),
        showUnchanged: String(showUnchanged),
      })
      if (ns) params.set('namespace', ns)
      const es = new EventSource(`/api/verdict/stream?${params}`)
      eventSourceRef.current = es

      es.onmessage = (ev) => {
        const payload = JSON.parse(ev.data) as { row?: VerdictRow; counts: VerdictResponse['counts'] }
        setRuns((prevRuns) =>
          prevRuns.map((r) => {
            if (r.id !== runId) return r
            const prev = r.result
            const rows = payload.row ? [...prev.rows, payload.row] : prev.rows
            const total =
              payload.counts.unchanged +
              payload.counts.newlyDropped +
              payload.counts.newlyAllowed +
              payload.counts.notSimulated +
              payload.counts.replySkipped
            return {
              ...r,
              result: {
                ...prev,
                rows,
                counts: { ...payload.counts, total },
                flowsSampled: total,
              },
            }
          })
        )
      }
      es.onerror = () => {
        setError('Live stream disconnected — check the candidate YAML is valid, or the backend may have stopped.')
        stopStreaming()
      }
      return
    }

    setLoading(true)
    try {
      const res = await runVerdict({ namespace: ns, candidateYAML, last, showUnchanged })
      const newRun: VerdictRunItem = {
        id: runId,
        timestamp: new Date(),
        namespace: ns,
        allNamespaces,
        last,
        showUnchanged,
        candidateYAML,
        isStreaming: false,
        result: res,
      }
      setRuns((prev) => (stackRuns ? [newRun, ...prev] : [newRun]))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid grid-cols-1 items-start gap-6 2xl:grid-cols-[380px_1fr]">
      {/* Control panel — sidebar */}
      <form
        onSubmit={handleSubmit}
        className="rise-in space-y-5 border border-line bg-panel p-5 2xl:sticky 2xl:top-6"
      >
        <div className="flex items-center justify-between">
          <SectionLabel>Scope</SectionLabel>
        </div>

        <NamespaceScope
          namespace={namespace}
          onNamespaceChange={setNamespace}
          allNamespaces={allNamespaces}
          onAllNamespacesChange={setAllNamespaces}
        />

        <div className="grid grid-cols-2 gap-3">
          <Field label="Last">
            <input
              type="number"
              min={1}
              value={last}
              onChange={(e) => setLast(Number(e.target.value) || 1)}
              className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
            />
          </Field>
          <div className="flex flex-col justify-end gap-2 pb-2">
            <CheckRow label="Show unchanged" checked={showUnchanged} onChange={setShowUnchanged} />
            <CheckRow label="Follow (live)" checked={follow} onChange={setFollow} />
          </div>
        </div>

        <div className="h-px bg-line" />

        <div className="flex items-center justify-between">
          <SectionLabel>Candidate policy</SectionLabel>
          <button
            type="button"
            onClick={() => setExpandedEditorOpen(true)}
            title="Open a wider editor to hand-edit this policy"
            className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-signal cursor-pointer"
          >
            ⤢ Expand
          </button>
        </div>
        {/* A real <button>, not a textarea, so Tab+Enter/Space opens the
            editor for free — a readOnly textarea never fires change and has
            no built-in "activate" key handling. */}
        <button
          type="button"
          onClick={() => setExpandedEditorOpen(true)}
          title="Click to edit in a wider view"
          className="w-full min-h-[18rem] cursor-pointer resize-y whitespace-pre-wrap border border-line bg-void px-3 py-2.5 text-left font-mono text-xs leading-relaxed text-ink focus:border-signal focus:outline-none"
        >
          {candidateYAML || (
            <span className="text-ink-faint">
              {'apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: ...\nspec:\n  ...'}
            </span>
          )}
          <span className="mt-2 block font-display text-[0.6rem] normal-case tracking-normal text-ink-faint">
            Click or press Enter to edit — opens a wider view
          </span>
        </button>
        {/* Keeps the native "required" submit guard the textarea used to
            provide, now that the visible control is a button, not a form field. */}
        <textarea value={candidateYAML} onChange={() => {}} required aria-hidden="true" tabIndex={-1} className="sr-only" />

        <div className="space-y-2">
          <CheckRow
            label="Stack runs (keep previous analyses)"
            checked={stackRuns}
            onChange={setStackRuns}
          />
        </div>

        <div className="flex gap-2">
          <button
            type="submit"
            disabled={loading || streaming}
            className="flex-1 bg-signal py-2.5 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
          >
            {loading ? 'Judging…' : streaming ? 'Streaming…' : follow ? 'Start following' : 'Run verdict'}
          </button>
          <button
            type="button"
            onClick={handleResetSession}
            title="Clear all results and reset the form to start fresh"
            className="border border-line bg-void/60 px-3 py-2.5 font-display text-xs font-semibold uppercase text-ink-dim hover:border-line-bright hover:text-ink transition-colors cursor-pointer"
          >
            Reset
          </button>
        </div>

        {streaming && (
          <div className="flex items-center justify-between border border-signal/30 bg-signal/5 px-3 py-2">
            <span className="flex items-center gap-2 text-xs text-signal">
              <span className="glow-pulse h-2 w-2 rounded-full bg-signal" />
              live — judging as flows arrive
            </span>
            <button
              type="button"
              onClick={stopStreaming}
              className="font-display text-[0.65rem] font-bold tracking-wide text-ink-dim uppercase hover:text-drop cursor-pointer"
            >
              Stop
            </button>
          </div>
        )}
      </form>

      {/* Results viewport */}
      <div className="min-w-0 space-y-6">
        {error && (
          <p className="rise-in border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">{error}</p>
        )}

        {runs.length > 0 && (
          <div className="flex items-center justify-between border-b border-line pb-3">
            <span className="font-display text-xs font-bold uppercase tracking-wider text-ink">
              {runs.length === 1 ? 'Analysis Result' : `Stacked Analyses (${runs.length})`}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleClearResults}
                className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-drop transition-colors cursor-pointer"
              >
                Clear all results
              </button>
            </div>
          </div>
        )}

        {runs.length === 0 && !loading && (
          <div className="border border-line bg-panel p-8 text-center text-ink-dim space-y-3">
            <p className="font-display text-xs uppercase tracking-wider text-ink">Ready to simulate</p>
            <p className="text-xs max-w-md mx-auto leading-relaxed">
              Pick a namespace scope, paste your candidate CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy, and click <strong className="text-signal">Run verdict</strong> to evaluate against live cluster traffic.
            </p>
          </div>
        )}

        {runs.map((run, runIndex) => (
          <RunCard
            key={run.id}
            run={run}
            runNumber={runs.length - runIndex}
            onOpenHelp={openHelp}
            onDuplicate={handleDuplicateToForm}
            onRemove={handleRemoveRun}
            onToggleCollapse={handleToggleCollapse}
            policyNamespace={policyNamespace}
            onAppendRuleToPolicy={onAppendRuleToPolicy}
          />
        ))}
      </div>

      {/* Informative Verdict Help Modal */}
      <VerdictHelpModal
        isOpen={helpOpen}
        onClose={() => setHelpOpen(false)}
        initialCategory={helpCategory}
      />

      <PolicyTextModal
        isOpen={expandedEditorOpen}
        onClose={() => setExpandedEditorOpen(false)}
        value={candidateYAML}
        onChange={setCandidateYAML}
      />
    </div>
  )
}

function RunCard({
  run,
  runNumber,
  onOpenHelp,
  onDuplicate,
  onRemove,
  onToggleCollapse,
  policyNamespace,
  onAppendRuleToPolicy,
}: {
  run: VerdictRunItem
  runNumber: number
  onOpenHelp: (cat: string) => void
  onDuplicate: (run: VerdictRunItem) => void
  onRemove: (id: string) => void
  onToggleCollapse: (id: string) => void
  policyNamespace: string
  onAppendRuleToPolicy?: (direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) => void
}) {
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null)
  const [exportCopied, setExportCopied] = useState(false)

  const result = run.result
  const rowsByCategory = result
    ? CATEGORY_ORDER.map((cat) => ({
        cat,
        rows: result.rows.filter((r) => r.change === cat),
      })).filter((g) => g.rows.length > 0)
    : []

  function handleExportMarkdown() {
    const rows = rowsByCategory.flatMap((g) => g.rows)
    navigator.clipboard.writeText(rowsToMarkdownTable(rows))
    setExportCopied(true)
    setTimeout(() => setExportCopied(false), 2000)
  }

  return (
    <div className="rise-in border border-line bg-panel space-y-4 p-5 shadow-sm">
      {/* Run Card Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex items-center gap-3">
          <span className="font-display text-xs font-bold uppercase tracking-wider text-signal">
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

        {/* Housekeeping, not the headline signal — kept as plain text/icon
            controls (no border chrome) so they don't visually compete with
            the newly-dropped/newly-allowed counts below, which are the
            actual answer this run exists to give. */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => onDuplicate(run)}
            title="Load this run's YAML and parameters back into the form"
            className="font-display text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-signal transition-colors cursor-pointer"
          >
            Duplicate to form
          </button>
          <button
            type="button"
            onClick={handleExportMarkdown}
            title="Copy the results table as Markdown, for pasting into a PR description or ticket"
            className="font-display text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-signal transition-colors cursor-pointer"
          >
            {exportCopied ? '✓ Copied!' : 'Export'}
          </button>
          <button
            type="button"
            onClick={() => onToggleCollapse(run.id)}
            className="font-display text-[0.65rem] font-semibold uppercase tracking-wider text-ink-faint hover:text-ink transition-colors cursor-pointer"
          >
            {run.isCollapsed ? 'Expand' : 'Collapse'}
          </button>
          <button
            type="button"
            onClick={() => onRemove(run.id)}
            title="Remove this analysis run"
            className="text-sm text-ink-faint hover:text-drop transition-colors cursor-pointer"
          >
            ✕
          </button>
        </div>
      </div>

      {!run.isCollapsed && (
        <div className="space-y-5">
          <p className="text-xs text-ink-dim">
            {run.isStreaming || result.flowsSampled > 0 ? (
              <>
                candidate {result.candidateRuleCount || 1} rule(s) · baseline {result.baselineRuleCount} rule(s)
                in <span className="text-ink">{result.namespace || 'all namespaces'}</span>
                {run.isStreaming
                  ? ` · ${result.flowsSampled} flow(s) judged so far`
                  : ` · ${result.flowsSampled}/${result.flowsRequested} flows sampled`}
              </>
            ) : (
              "no flows observed for this scope in Hubble's current buffer — nothing to simulate"
            )}
          </p>

          <div className="flex flex-wrap items-center gap-2">
            <CountChip
              label="unchanged"
              value={result.counts.unchanged}
              className={CHANGE_STYLES.UNCHANGED}
              onClick={() => onOpenHelp('unchanged')}
            />
            <CountChip
              label="newly dropped"
              value={result.counts.newlyDropped}
              className={HEADLINE_CHIP_STYLES.NEWLY_DROPPED}
              filled
              onClick={() => onOpenHelp('newly dropped')}
            />
            <CountChip
              label="newly allowed"
              value={result.counts.newlyAllowed}
              className={HEADLINE_CHIP_STYLES.NEWLY_ALLOWED}
              filled
              onClick={() => onOpenHelp('newly allowed')}
            />
            <CountChip
              label="not simulated"
              value={result.counts.notSimulated}
              className="border-line-bright bg-panel-raised text-ink-dim"
              onClick={() => onOpenHelp('not simulated')}
            />
            <CountChip
              label="reply skipped"
              value={result.counts.replySkipped}
              className="border-line-bright bg-panel-raised text-ink-dim"
              onClick={() => onOpenHelp('reply skipped')}
            />
          </div>

          {result.counts.newlyDropped > 0 && (
            <p className="border border-drop/40 bg-drop/10 px-4 py-3 text-sm font-semibold text-drop">
              {result.counts.newlyDropped} real flow(s) would BREAK if this candidate merged as-is — review
              below before shipping it.
            </p>
          )}

          {/* Flow Graph with interactive selection and anti-collision labels */}
          <VerdictGraph
            rows={result.rows}
            selectedNodeId={selectedGraphNode}
            onSelectNode={setSelectedGraphNode}
          />

          {rowsByCategory.length === 0 &&
            !run.isStreaming &&
            (result.flowsSampled === 0 ? (
              <p className="text-sm text-ink-dim">
                No flows observed for this scope in Hubble's current buffer — nothing to simulate.
              </p>
            ) : (
              <p className="text-sm text-unchanged">
                ✓ No regressions — {result.flowsSampled} flow(s) sampled, all unchanged
                {!run.showUnchanged && result.counts.unchanged > 0
                  ? ' (enable "Show unchanged" above to see them)'
                  : ''}
                .
              </p>
            ))}

          {rowsByCategory.map(({ cat, rows }) => (
            <div key={cat} className="overflow-x-auto border border-line">
              <table className="w-full min-w-[640px] text-left text-sm">
                <thead className="border-b border-line bg-panel-raised">
                  <tr>
                    {['Change', 'Source', 'Destination', 'Port', 'Seen', 'Why', ''].map((h) => (
                      <th
                        key={h}
                        className="px-3 py-2 text-[0.65rem] font-semibold tracking-[0.1em] text-ink-dim uppercase"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {rows.map((row, i) => {
                    const srcId = `src:${row.source}`
                    const dstId = `dst:${row.destination}`
                    return (
                    <tr key={i} className="hover:bg-panel-raised/60">
                      <td className="px-3 py-2">
                        <span
                          className={`border px-2 py-0.5 text-[0.65rem] font-semibold ${CHANGE_STYLES[row.change]}`}
                        >
                          {row.change}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">
                        <GraphNodeLink
                          selected={selectedGraphNode === srcId}
                          onClick={() => setSelectedGraphNode((prev) => (prev === srcId ? null : srcId))}
                        >
                          {row.source}
                        </GraphNodeLink>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">
                        <GraphNodeLink
                          selected={selectedGraphNode === dstId}
                          onClick={() => setSelectedGraphNode((prev) => (prev === dstId ? null : dstId))}
                        >
                          {row.destination}
                        </GraphNodeLink>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">
                        {row.protocol}:{row.port}
                      </td>
                      <td className="px-3 py-2 text-xs text-ink-faint">{row.count > 1 ? `${row.count}×` : '—'}</td>
                      <td className="px-3 py-2 text-xs text-ink-dim">{row.explanation}</td>
                      <td className="px-3 py-2">
                        {row.change !== 'UNCHANGED' && onAppendRuleToPolicy && (
                          <AddToPolicyButton
                            row={row}
                            policyNamespace={policyNamespace}
                            onAppend={onAppendRuleToPolicy}
                          />
                        )}
                      </td>
                    </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase w-full">
      <span className="h-px flex-1 bg-line" />
      {children}
      <span className="h-px flex-1 bg-line" />
    </div>
  )
}

// Makes a table cell's source/destination text clickable, selecting the
// matching node in the VerdictGraph above — the same isolation effect as
// clicking the box directly, triggered from the row instead.
type PeerFields = { endpoints: { matchLabels: Record<string, string>; namespace?: string }[]; cidrs: string[]; entities: string[] }

function peerFieldsFromClassification(
  classified: ReturnType<typeof classifyTrafficPeer>,
  peerNamespace?: string
): PeerFields | null {
  if (classified.kind === 'pod' && classified.label) {
    const [key, value] = classified.label
    return { endpoints: [{ matchLabels: { [key]: value }, namespace: peerNamespace }], cidrs: [], entities: [] }
  }
  if (classified.kind === 'entity' && classified.entity) {
    return { endpoints: [], cidrs: [], entities: [classified.entity] }
  }
  if (classified.kind === 'cidr' && classified.cidr) {
    return { endpoints: [], cidrs: [classified.cidr], entities: [] }
  }
  return null
}

const VALID_PROTOCOLS = new Set<Protocol>(['TCP', 'UDP', 'ICMP', 'ANY'])

// Turns a flagged verdict row (traffic that would break, or newly open up)
// directly into a rule on the Policy Editor's in-progress draft, so fixing
// a real regression found here doesn't mean re-typing it by hand in the
// other tab. Direction is inferred from which side of the flow shares the
// draft policy's own namespace: destination matching means this is an
// ingress rule (peer = source); source matching means egress (peer =
// destination). A row that matches neither side isn't obviously about
// this draft policy, so the button doesn't render for it.
function AddToPolicyButton({
  row,
  policyNamespace,
  onAppend,
}: {
  row: VerdictRow
  policyNamespace: string
  onAppend: (direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) => void
}) {
  const [busy, setBusy] = useState(false)
  const [added, setAdded] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Only clicking elsewhere dismissed this error before — Escape is the
  // conventional keyboard dismiss this app's modals already use, and a
  // keyboard-only user had no way to close it otherwise.
  useEffect(() => {
    if (!error) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setError(null)
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [error])

  const dstNamespace = parseNamespacePod(row.destination)?.namespace
  const srcNamespace = parseNamespacePod(row.source)?.namespace
  const direction: 'ingress' | 'egress' | null =
    policyNamespace && dstNamespace === policyNamespace
      ? 'ingress'
      : policyNamespace && srcNamespace === policyNamespace
      ? 'egress'
      : null

  if (!direction) return null

  const peer = direction === 'ingress' ? row.source : row.destination
  const peerNamespace = parseNamespacePod(peer)?.namespace

  async function handleClick() {
    setBusy(true)
    setError(null)
    try {
      const peerPodsByNs = peerNamespace ? { [peerNamespace]: (await fetchPods(peerNamespace)).pods } : {}
      const classified = classifyTrafficPeer(peer, peerPodsByNs)
      const fields = peerFieldsFromClassification(classified, peerNamespace)
      if (!fields) {
        setError(`Can't represent "${peer}" as a rule peer yet`)
        setBusy(false)
        return
      }

      const protocol: Protocol = VALID_PROTOCOLS.has(row.protocol as Protocol) ? (row.protocol as Protocol) : 'ANY'
      const toPorts = [{ port: String(row.port), protocol }]

      if (direction === 'ingress') {
        onAppend('ingress', {
          id: `ingress-${Date.now()}`,
          fromEndpoints: fields.endpoints,
          fromCIDRs: fields.cidrs,
          fromEntities: fields.entities,
          toPorts,
        })
      } else {
        onAppend('egress', {
          id: `egress-${Date.now()}`,
          toEndpoints: fields.endpoints,
          toCIDRs: fields.cidrs,
          toEntities: fields.entities,
          toServices: [],
          toPorts,
        })
      }
      setBusy(false)
      setAdded(true)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setBusy(false)
    }
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={handleClick}
        disabled={busy || added}
        title={
          added
            ? 'Already added to the in-progress policy'
            : `Add this ${direction === 'ingress' ? 'source' : 'destination'} as a rule on the in-progress policy (${policyNamespace})`
        }
        className="whitespace-nowrap border border-signal/40 bg-signal/5 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal/10 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
      >
        {added ? '✓ Added' : busy ? 'Adding…' : '+ Add to Policy'}
      </button>
      {error && (
        <div
          role="alert"
          className="absolute right-0 top-full z-10 mt-1 w-56 border border-drop/40 bg-panel p-2 text-[0.65rem] text-drop shadow-lg"
        >
          {error}
        </div>
      )}
    </div>
  )
}

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

function CountChip({
  label,
  value,
  className,
  filled,
  onClick,
}: {
  label: string
  value: number
  className: string
  // True for the filled (bg-drop/bg-allow) headline chips, whose base text
  // is text-void — the glyph's own "dim" shade has to be void-based there
  // too, or text-ink-faint (tuned for dark/void backgrounds) disappears
  // against a bright solid fill.
  filled?: boolean
  onClick?: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={`Click to learn more about "${label}" flows`}
      className={`group border px-2.5 py-1 text-xs font-medium ${className} cursor-pointer hover:brightness-110 active:scale-98 transition-all flex items-center gap-1.5`}
    >
      <span className="font-semibold">{value}</span>
      <span>{label}</span>
      {/* Deliberately not colored by the chip's own category color — this
          is the one part of the chip that's actually clickable-for-info,
          so it reads as a distinct affordance instead of blending into the
          (non-interactive-looking) count + label. */}
      <span
        className={
          filled
            ? 'rounded-full text-void/50 transition-colors group-hover:text-void group-focus-visible:text-void group-focus-visible:ring-1 group-focus-visible:ring-void'
            : 'rounded-full text-ink-faint transition-colors group-hover:text-signal group-focus-visible:text-signal group-focus-visible:ring-1 group-focus-visible:ring-signal'
        }
      >
        ⓘ
      </span>
    </button>
  )
}
