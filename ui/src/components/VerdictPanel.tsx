import { useEffect, useMemo, useRef, useState } from 'react'
import { ConnectivityTestsPanel } from './ConnectivityTestsPanel'
import { fetchPods, fetchPolicyWorkloads, runVerdict, type WorkloadsResult, type VerdictChange, type VerdictResponse, type VerdictRow } from '../api'
import { classifyTrafficPeer } from './RuleEditorCard'
import { groupRows } from '../shared/groupRows'
import { formatElapsed, useElapsedMs } from '../shared/elapsed'
import { downloadTextFile, l7Text, verdictRowsToCSV, verdictRowsToText } from '../shared/tableExport'
import { CheckRow, Field, NamespaceScope } from './NamespaceScope'
import { PolicyTextModal } from './PolicyTextModal'
import { VerdictGraph } from './VerdictGraph'
import { VerdictHelpModal } from './VerdictHelpModal'
import { parseNamespacePod } from '../shared/podLabels'
import { appendPolicyDocument } from '../shared/workloadException'
import { WorkloadExceptionMenu } from './WorkloadExceptionMenu'
import { SaveToWorkspace } from './SaveToWorkspace'
import { firstPolicyName, loadVerdictForm, persistVerdictForm, type NewSavedPolicy } from '../shared/workspace'
import {
  appendFlowFilter,
  describeFlowFilter,
  flowFilterParams,
  EMPTY_FLOW_FILTER,
  filterSuggestions,
  isFlowFilterEmpty,
  type FlowFilter,
} from '../shared/flowFilter'
import { FlowFilterFields } from './FlowFilterFields'
import type { EgressRule, IngressRule, Protocol } from '../policy'
import { runsWithLiveGraphs } from '../shared/graphBudget'
import { GraphPlaceholder } from './GraphPlaceholder'
import { GraphNodeLink } from './GraphNodeLink'
import { CountChip, EmptyState, ResultsHeader, SectionLabel } from './Chips'
import { CHANGE_STYLES, FIELD_ROW_OFFSET, HEADLINE_CHIP_STYLES, META_CHIP, TEXT_ACTION } from '../shared/chipStyles'

const CATEGORY_ORDER: VerdictChange[] = ['NEWLY_DROPPED', 'NEWLY_ALLOWED', 'L7_CHANGED', 'UNCHANGED']

// Mirrors the results table's own columns/order exactly, so what gets
// pasted into a PR description or ticket matches what's on screen.
function rowsToMarkdownTable(rows: VerdictRow[]): string {
  const escapeCell = (v: string) => v.replace(/\|/g, '\\|')
  const header = '| Change | Source | Destination | Port | Seen | Why |\n| --- | --- | --- | --- | --- | --- |'
  const lines = rows.map(
    (r) =>
      `| ${r.change} | ${escapeCell(r.source)} | ${escapeCell(r.destination)} | ${r.protocol}:${r.port} | ${
        r.count > 1 ? `${r.count}×` : '—'
      } | ${escapeCell(r.explanation)}${l7Text(r) ? ` (L7 ${escapeCell(l7Text(r))})` : ''} |`
  )
  return [header, ...lines].join('\n')
}

const EMPTY_COUNTS = {
  unchanged: 0,
  newlyDropped: 0,
  newlyAllowed: 0,
  l7Changed: 0,
  notSimulated: 0,
  replySkipped: 0,
  total: 0,
}

export interface VerdictRunItem {
  replaceExisting: boolean
  id: string
  timestamp: Date
  namespace: string
  allNamespaces: boolean
  last: number
  showUnchanged: boolean
  candidateYAML: string
  filter: FlowFilter
  isStreaming: boolean
  result: VerdictResponse
  isCollapsed?: boolean
  // How long the run took, wall clock as seen from the browser. Unset while
  // a live stream is still running — its card ticks from timestamp instead.
  durationMs?: number
}

// A request (from "Test in Verdict Simulator" or the workspace's "Open in
// Verdict") to load a candidate into the form. token makes re-loading the
// exact same content apply again — two plain string props wouldn't change,
// so the effect wouldn't fire.
export interface VerdictLoad {
  namespace: string
  allNamespaces?: boolean
  candidateYAML: string
  savedName?: string
  token: number
}

export interface VerdictPanelProps {
  active?: boolean
  load?: VerdictLoad | null
  onSavePolicy?: (entry: NewSavedPolicy) => boolean
  // The Policy Editor's in-progress draft namespace and a way to append a
  // rule to it — lets a NEWLY_DROPPED/NEWLY_ALLOWED row be turned straight
  // into a rule on that draft without retyping anything, then jumps to the
  // Policy Editor with the new rule selected for review.
  policyNamespace?: string
  onAppendRuleToPolicy?: (direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) => void
}

export function VerdictPanel({
  active = false,
  load,
  onSavePolicy,
  policyNamespace = '',
  onAppendRuleToPolicy,
}: VerdictPanelProps = {}) {
  // Restored from the last session (auto-saved below), so a reload doesn't
  // throw away the candidate being worked on — appended Allow/Deny
  // exceptions included. Runs aren't restored: they're snapshots of live
  // traffic at that moment, and stale results would read as current.
  const [stored] = useState(loadVerdictForm)
  const [replaceExisting, setReplaceExisting] = useState(stored.replaceExisting)
  const [resetGeneration, setResetGeneration] = useState(0)
  const [probeRunning, setProbeRunning] = useState(false)
  const [namespace, setNamespace] = useState(stored.namespace)
  const [allNamespaces, setAllNamespaces] = useState(stored.allNamespaces)
  const [last, setLast] = useState(stored.last)
  const [showUnchanged, setShowUnchanged] = useState(stored.showUnchanged)
  const [follow, setFollow] = useState(false)
  const [candidateYAML, setCandidateYAML] = useState(stored.candidateYAML)
  const [savedName, setSavedName] = useState(stored.savedName)
  const [filter, setFilter] = useState(stored.filter)
  const [stackRuns, setStackRuns] = useState(false)

  const [runs, setRuns] = useState<VerdictRunItem[]>([])
  const liveGraphRuns = useMemo(() => runsWithLiveGraphs(runs), [runs])
  const [loading, setLoading] = useState(false)
  const [loadingSince, setLoadingSince] = useState<number | null>(null)
  const loadingElapsedMs = useElapsedMs(loadingSince)
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [workloads, setWorkloads] = useState<WorkloadsResult | null>(null)
  const [workloadsLoading, setWorkloadsLoading] = useState(false)

  // Help modal state
  const [helpOpen, setHelpOpen] = useState(false)
  const [helpCategory, setHelpCategory] = useState<string | null>(null)
  const [expandedEditorOpen, setExpandedEditorOpen] = useState(false)

  const eventSourceRef = useRef<EventSource | null>(null)
  const streamRunIdRef = useRef<string | null>(null)
  const requestGenerationRef = useRef(0)

  useEffect(() => {
    if (!load) return
    setNamespace(load.namespace)
    if (load.allNamespaces !== undefined) setAllNamespaces(load.allNamespaces)
    setCandidateYAML(load.candidateYAML)
    setSavedName(load.savedName ?? '')
  }, [load])

  useEffect(() => {
    persistVerdictForm({ namespace, allNamespaces, last, showUnchanged, candidateYAML, savedName, filter, replaceExisting })
  }, [namespace, allNamespaces, last, showUnchanged, candidateYAML, savedName, filter, replaceExisting])

  function handleSave(name: string): boolean {
    const updated =
      onSavePolicy?.({ name, origin: 'verdict', candidateYAML, namespace, allNamespaces }) ?? false
    setSavedName(name)
    return updated
  }

  useEffect(() => () => eventSourceRef.current?.close(), [])

  function openHelp(category?: string) {
    setHelpCategory(category || null)
    setHelpOpen(true)
  }

  function stopStreaming() {
    eventSourceRef.current?.close()
    eventSourceRef.current = null
    setStreaming(false)
    // Freeze the stopped stream's clock at the moment it ended.
    const runId = streamRunIdRef.current
    streamRunIdRef.current = null
    if (runId) {
      const endedAt = Date.now()
      setRuns((prev) =>
        prev.map((r) => (r.id === runId ? { ...r, durationMs: endedAt - r.timestamp.getTime() } : r))
      )
    }
  }

  function handleResetSession() {
    if (probeRunning) return
    setResetGeneration((generation) => generation + 1)
    setReplaceExisting(true)
    stopStreaming()
    requestGenerationRef.current++
    setLoading(false)
    setLoadingSince(null)
    setRuns([])
    setError(null)
    setNamespace('')
    setAllNamespaces(false)
    setLast(50)
    setShowUnchanged(false)
    setFollow(false)
    setCandidateYAML('')
    setSavedName('')
    setFilter(EMPTY_FLOW_FILTER)
  }

  function handleClearResults() {
    stopStreaming()
    requestGenerationRef.current++
    setLoading(false)
    setLoadingSince(null)
    setRuns([])
    setError(null)
  }

  function handleDuplicateToForm(run: VerdictRunItem) {
    setReplaceExisting(run.replaceExisting)
    setNamespace(run.namespace)
    setAllNamespaces(run.allNamespaces)
    setLast(run.last)
    setShowUnchanged(run.showUnchanged)
    setCandidateYAML(run.candidateYAML)
    setFilter(run.filter)
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
        replaceExisting,
        candidateYAML,
        filter,
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
      streamRunIdRef.current = runId

      const params = new URLSearchParams({
        candidateYAML,
        last: String(last),
        showUnchanged: String(showUnchanged),
        replaceExisting: String(replaceExisting),
      })
      if (ns) params.set('namespace', ns)
      appendFlowFilter(params, filter)
      const es = new EventSource(`/api/verdict/stream?${params}`)
      eventSourceRef.current = es

      es.onmessage = (ev) => {
        const payload = JSON.parse(ev.data) as {
          row?: VerdictRow
          counts: VerdictResponse['counts']
          skippedPolicies?: string[]
          warnings?: string[]
          baselineRuleCount?: number
          candidateRuleCount?: number
          context?: string
          apiServer?: string
        }
        setRuns((prevRuns) =>
          prevRuns.map((r) => {
            if (r.id !== runId) return r
            const prev = r.result
            const rows = payload.row ? [...prev.rows, payload.row] : prev.rows
            const total =
              payload.counts.unchanged +
              payload.counts.newlyDropped +
              payload.counts.newlyAllowed +
              payload.counts.l7Changed +
              payload.counts.notSimulated +
              payload.counts.replySkipped
            return {
              ...r,
              result: {
                ...prev,
                rows,
                counts: { ...payload.counts, total },
                flowsSampled: total,
                baselineRuleCount: payload.baselineRuleCount ?? prev.baselineRuleCount,
                candidateRuleCount: payload.candidateRuleCount ?? prev.candidateRuleCount,
                context: payload.context ?? prev.context,
                apiServer: payload.apiServer ?? prev.apiServer,
                skippedPolicies: payload.skippedPolicies ?? prev.skippedPolicies,
                warnings: payload.warnings ?? prev.warnings,
              },
            }
          })
        )
      }
      es.onerror = () => {
        const generic = 'Live stream disconnected — check the candidate YAML is valid, or the backend may have stopped.'
        // EventSource hides the HTTP error body. CLOSED means the server
        // refused the stream outright (not a mid-stream drop it would retry),
        // so one plain fetch returns promptly with the real reason.
        if (es.readyState === EventSource.CLOSED) {
          fetch(`/api/verdict/stream?${params}`)
            .then(async (res) => (res.ok ? generic : (await res.text()).trim() || generic))
            .catch(() => generic)
            .then(setError)
        } else {
          setError(generic)
        }
        stopStreaming()
      }
      return
    }

    await runOneShot({ namespace: ns, allNamespaces, last, showUnchanged, candidateYAML, filter, replaceExisting }, stackRuns)
  }

  async function runOneShot(
    params: Pick<VerdictRunItem, 'namespace' | 'allNamespaces' | 'last' | 'showUnchanged' | 'candidateYAML' | 'filter' | 'replaceExisting'>,
    stack: boolean
  ) {
    const generation = ++requestGenerationRef.current
    const startedAt = new Date()
    setLoading(true)
    setLoadingSince(startedAt.getTime())
    setError(null)
    try {
      const res = await runVerdict({
        namespace: params.namespace,
        candidateYAML: params.candidateYAML,
        last: params.last,
        showUnchanged: params.showUnchanged,
        replaceExisting: params.replaceExisting,
        ...flowFilterParams(params.filter),
      })
      if (generation !== requestGenerationRef.current) return
      const newRun: VerdictRunItem = {
        ...params,
        id: `run-${Date.now()}`,
        timestamp: startedAt,
        isStreaming: false,
        result: res,
        durationMs: Date.now() - startedAt.getTime(),
      }
      setRuns((prev) => (stack ? [newRun, ...prev] : [newRun]))
    } catch (err) {
      if (generation !== requestGenerationRef.current) return
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      if (generation === requestGenerationRef.current) {
        setLoading(false)
        setLoadingSince(null)
      }
    }
  }

  // A row's Allow/Deny exception: appended to the candidate that produced
  // that run, loaded back into the form, and re-judged right away as a new
  // stacked run — so the previous run stays visible for comparison.
  async function handleAddException(run: VerdictRunItem, policyYAML: string) {
    stopStreaming()
    const next = { ...run, candidateYAML: appendPolicyDocument(run.candidateYAML, policyYAML) }
    handleDuplicateToForm(next)
    await runOneShot(next, true)
  }

  // Selection is decided server-side by Cilium's own engine, not by
  // matching labels in the browser, so matchExpressions and the derived
  // namespace-label / service-account keys behave exactly as in the agent.
  async function handleCheckWorkloads() {
    setWorkloadsLoading(true)
    setError(null)
    try {
      setWorkloads(await fetchPolicyWorkloads(allNamespaces ? '' : namespace, candidateYAML))
    } catch (e) {
      setWorkloads(null)
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setWorkloadsLoading(false)
    }
  }

  return (
    <>
      {/* Setup on top as two balanced panels — scope (with filters) on the
          left, the candidate policy and its run actions on the right — and
          the results below at full width, where the graphs need the room.
          Stacked on narrower screens. */}
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 items-stretch gap-6 xl:grid-cols-2">
          <div className="rise-in min-w-0 space-y-5 border border-line bg-panel p-5">
            <SectionLabel>Scope</SectionLabel>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(0,1fr)_6.5rem_auto]">
              <NamespaceScope
                namespace={namespace}
                onNamespaceChange={setNamespace}
                allNamespaces={allNamespaces}
                onAllNamespacesChange={setAllNamespaces}
              />
              <Field label="Last">
                <input
                  type="number"
                  min={1}
                  value={last}
                  onChange={(e) => setLast(Number(e.target.value) || 1)}
                  className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
                />
              </Field>
              <div className={`flex flex-col gap-2 ${FIELD_ROW_OFFSET}`}>
                <CheckRow label="Show unchanged" checked={showUnchanged} onChange={setShowUnchanged} />
                <CheckRow label="Replace matching live policies" checked={replaceExisting} onChange={setReplaceExisting} />
                <CheckRow label="Follow (live)" checked={follow} onChange={setFollow} />
                <CheckRow label="Stack runs" checked={stackRuns} onChange={setStackRuns} />
              </div>
            </div>
            <p className="text-xs text-ink-dim">Replacement models an update to matching live policy names. Uncheck for additive simulation: keep live policies and add the candidate. Neither mode applies a policy.</p>

            <FlowFilterFields
              filter={filter}
              onChange={setFilter}
              suggestions={filterSuggestions(runs.flatMap((r) => r.result.rows))}
              intro="Judge only matching flows; other traffic isn't judged, so use this to investigate, not to sign off. Verdict is today's: DROPPED asks which current drops the candidate would allow."
            />
          </div>

          {/* Candidate policy YAML & run actions */}
          <div className="rise-in flex min-w-0 flex-col gap-3 border border-line bg-panel p-5">
            <SectionLabel
              actions={
                <>
                {onSavePolicy && (
                  <SaveToWorkspace
                    defaultName={savedName || firstPolicyName(candidateYAML) || 'candidate'}
                    disabled={!candidateYAML.trim()}
                    onSave={handleSave}
                  />
                )}
                <button
                  type="button"
                  onClick={() => setExpandedEditorOpen(true)}
                  title="Open a wider editor to hand-edit this policy"
                  className={TEXT_ACTION}
                >
                  ⤢ Expand
                </button>
                </>
              }
            >
              Candidate policy
            </SectionLabel>
            {savedName && (
              <p className="-mt-1 text-[0.65rem] text-ink-faint">
                Workspace entry: <span className="font-mono text-ink-dim">{savedName}</span> (edits auto-save
                in this browser; Save updates the entry)
              </p>
            )}

            {/* Run/Reset above the YAML box, not below it — with a long
                candidate policy the box itself can run well past the fold,
                and the action that actually matters shouldn't be something
                you have to scroll past a wall of YAML to find (same reason
                the Policy Editor tab puts "Test in Verdict Simulator" above
                its YAML output rather than after it). */}
            <div className="flex flex-wrap gap-2">
              <button
                type="submit"
                disabled={loading || streaming}
                className="flex-1 bg-signal py-2.5 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
              >
                {loading ? `Judging… ${formatElapsed(loadingElapsedMs)}` : streaming ? 'Streaming…' : follow ? 'Start following' : 'Run verdict'}
              </button>
              <button
                type="button"
                onClick={handleResetSession}
                disabled={probeRunning}
                title="Clear all results and reset the form to start fresh"
                className="border border-line bg-void/60 px-3 py-2.5 font-display text-xs font-semibold uppercase text-ink-dim hover:border-line-bright hover:text-ink transition-colors cursor-pointer"
              >
                Reset
              </button>
            </div>
            <button
              type="button"
              disabled={workloadsLoading || !candidateYAML.trim()}
              onClick={handleCheckWorkloads}
              title="List live pods and show which ones this policy's endpointSelector selects"
              className="w-full border border-line bg-void/60 py-2 font-display text-xs font-semibold uppercase tracking-wider text-ink hover:border-signal hover:text-signal transition-colors disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
            >
              {workloadsLoading ? 'Checking…' : 'Which workloads does it select?'}
            </button>

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

            {/* A real, editable textarea so the user can paste a policy
                straight in (Ctrl+V / middle-click) without first opening the
                modal — the old read-only <button> swallowed paste entirely.
                The expand button still opens the wider editor. */}
            <textarea
              aria-label="Candidate YAML"
              value={candidateYAML}
              onChange={(e) => setCandidateYAML(e.target.value)}
              required
              spellCheck={false}
              placeholder={'apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: ...\nspec:\n  ...'}
              className="w-full min-h-[16rem] flex-1 resize-y border border-line bg-void px-3 py-2.5 font-mono text-xs leading-relaxed text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none"
            />
          </div>
        </div>

        {error && (
          <p className="rise-in border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">{error}</p>
        )}

        {workloads && (
          <div className="rise-in space-y-3 border border-line bg-panel p-5">
            <SectionLabel
              actions={
              <button
                type="button"
                onClick={() => setWorkloads(null)}
                className={TEXT_ACTION}
              >
                Dismiss
              </button>
              }
            >
              Selected workloads
            </SectionLabel>
            {!workloads.valid ? (
              <p className="text-sm text-drop">{workloads.error}</p>
            ) : (
              <>
                <p className="text-xs text-ink-dim">
                  {workloads.workloads.filter((w) => w.selected).length} of {workloads.workloads.length} running pods are selected by this policy's endpointSelector.
                  Selection comes from Cilium's own engine. Run the verdict to see which observed flows it blocks.
                </p>
                <ul className="max-h-72 divide-y divide-line overflow-auto border border-line text-xs">
                  {workloads.workloads.map((w) => (
                    <li key={`${w.namespace}/${w.name}`} className="flex items-center justify-between gap-3 px-3 py-2">
                      <span className="min-w-0 truncate">
                        <span className="text-ink">{w.namespace}/{w.name}</span>
                        <span className="ml-2 text-ink-dim">sa: {w.serviceAccount}</span>
                      </span>
                      <span
                        className={`shrink-0 border px-2 py-0.5 font-display text-[0.6rem] font-bold uppercase tracking-wider ${
                          w.selected ? 'border-drop/40 bg-drop/10 text-drop' : 'border-unchanged/40 bg-unchanged/10 text-unchanged'
                        }`}
                      >
                        {w.selected ? `selected · ${[w.egress && 'egress', w.ingress && 'ingress'].filter(Boolean).join('+')}` : 'not selected'}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}

      </form>

      <ConnectivityTestsPanel active={active} candidateYAML={candidateYAML} namespace={namespace} allNamespaces={allNamespaces} replaceExisting={replaceExisting} resetGeneration={resetGeneration} onRunningChange={setProbeRunning} onOpenHelp={openHelp} />

      <div className="mt-6 space-y-6">
        {runs.length > 0 && (
          <ResultsHeader
            title={runs.length === 1 ? 'Verdict result' : `Stacked verdicts (${runs.length})`}
            clearLabel="Clear all results"
            onClear={handleClearResults}
          />
        )}

        {runs.length === 0 && !loading && (
          <EmptyState title="Ready to simulate">
            Pick a namespace scope, paste your candidate CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy, and click <strong className="text-signal">Run verdict</strong> to evaluate against live cluster traffic.
          </EmptyState>
        )}

        {runs.map((run, runIndex) => (
          <RunCard
            key={run.id}
            run={run}
            graphLive={liveGraphRuns.has(run.id)}
            runNumber={runs.length - runIndex}
            onOpenHelp={openHelp}
            onDuplicate={handleDuplicateToForm}
            onRemove={handleRemoveRun}
            onToggleCollapse={handleToggleCollapse}
            policyNamespace={policyNamespace}
            onAppendRuleToPolicy={onAppendRuleToPolicy}
            onAddException={(yaml) => handleAddException(run, yaml)}
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
    </>
  )
}

// A live stream ticks until stopped; a finished run shows its final time.
function RunDuration({ run }: { run: VerdictRunItem }) {
  const live = run.durationMs === undefined && run.isStreaming
  const elapsedMs = useElapsedMs(live ? run.timestamp.getTime() : null)
  const ms = run.durationMs ?? (live ? elapsedMs : undefined)
  if (ms === undefined) return null
  return (
    <span
      title={live ? 'Running for' : 'Wall-clock time this run took, from request to result'}
      className={`font-mono text-[0.7rem] tabular-nums ${live ? 'text-signal' : 'text-ink-faint'}`}
    >
      {formatElapsed(ms)}
    </span>
  )
}

const VERDICT_GRAPH_HINTS = [
  'pick a single namespace instead of all namespaces',
  'add a destination filter',
  'turn off Show unchanged',
  'lower Last',
]

function RunCard({
  run,
  graphLive,
  runNumber,
  onOpenHelp,
  onDuplicate,
  onRemove,
  onToggleCollapse,
  policyNamespace,
  onAppendRuleToPolicy,
  onAddException,
}: {
  run: VerdictRunItem
  // False for an older stacked run past LIVE_GRAPH_RUN_LIMIT (see
  // shared/graphBudget.ts): its graph waits behind a "Show graph" button.
  graphLive: boolean
  runNumber: number
  onOpenHelp: (cat: string) => void
  onDuplicate: (run: VerdictRunItem) => void
  onRemove: (id: string) => void
  onToggleCollapse: (id: string) => void
  policyNamespace: string
  onAppendRuleToPolicy?: (direction: 'ingress' | 'egress', rule: IngressRule | EgressRule) => void
  onAddException: (policyYAML: string) => void
}) {
  const [selectedGraphNode, setSelectedGraphNode] = useState<string | null>(null)
  const [exportCopied, setExportCopied] = useState(false)
  const [showPausedGraph, setShowPausedGraph] = useState(false)
  const [tableCopied, setTableCopied] = useState(false)
  // Per run card, not a form option: grouping is a view over rows already
  // received, so it applies to a live stream and to finished runs alike.
  const [grouped, setGrouped] = useState(false)

  const result = run.result
  const shownRows = result ? (grouped ? groupRows(result.rows) : result.rows) : []
  const rowsByCategory = result
    ? CATEGORY_ORDER.map((cat) => ({
        cat,
        rows: shownRows.filter((r) => r.change === cat),
      })).filter((g) => g.rows.length > 0)
    : []

  function handleExportMarkdown() {
    const rows = rowsByCategory.flatMap((g) => g.rows)
    navigator.clipboard.writeText(rowsToMarkdownTable(rows))
    setExportCopied(true)
    setTimeout(() => setExportCopied(false), 2000)
  }

  // Same row set and order as the on-screen table (grouped by change).
  function handleCopyTable() {
    navigator.clipboard.writeText(verdictRowsToText(rowsByCategory.flatMap((g) => g.rows)))
    setTableCopied(true)
    setTimeout(() => setTableCopied(false), 2000)
  }

  function handleDownloadCSV() {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    downloadTextFile(
      `guardbee-verdict-${run.namespace || 'all-namespaces'}-${stamp}.csv`,
      verdictRowsToCSV(rowsByCategory.flatMap((g) => g.rows)),
      'text/csv'
    )
  }

  return (
    <div className="rise-in border border-line bg-panel space-y-4 p-5 shadow-sm">
      {/* Run Card Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-3">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-display text-xs font-bold uppercase tracking-wider text-signal">
            Run #{runNumber}
          </span>
          <span className="text-[0.7rem] font-mono text-ink-faint">
            {run.timestamp.toLocaleTimeString()}
          </span>
          <RunDuration run={run} />
          <span className={`${META_CHIP} text-ink-dim`}>
            {run.replaceExisting ? 'mode: replace matching policies' : 'mode: additive'}
          </span>
          {run.result.context && (
            <span
              title={`The cluster this run judged: kubeconfig context ${run.result.context}${
                run.result.apiServer ? ` (${run.result.apiServer})` : ''
              }`}
              className={`${META_CHIP} text-ink`}
            >
              context: {run.result.context}
            </span>
          )}
          <span className={`${META_CHIP} text-ink`}>
            {run.namespace ? `namespace: ${run.namespace}` : 'all namespaces'}
          </span>
          <span className={`${META_CHIP} text-ink-dim`}>
            last: {run.last}
          </span>
          {!isFlowFilterEmpty(run.filter) && (
            <span
              title="Only matching flows were fetched and judged. Anything the candidate does to other traffic isn't in this run."
              className="border border-signal/40 bg-signal/5 px-2 py-0.5 font-mono text-[0.7rem] text-signal"
            >
              only: {describeFlowFilter(run.filter)}
            </span>
          )}
        </div>

        {/* Housekeeping, not the headline signal — kept as plain text/icon
            controls (no border chrome) so they don't visually compete with
            the newly-dropped/newly-allowed counts below, which are the
            actual answer this run exists to give. */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() => onDuplicate(run)}
            title="Load this run's YAML and parameters back into the form"
            className={TEXT_ACTION}
          >
            Duplicate to form
          </button>
          <button
            type="button"
            onClick={() => setGrouped((g) => !g)}
            aria-pressed={grouped}
            title="Collapse rows with the same change, source, destination and port into one, with a count in the Seen column"
            className={`${TEXT_ACTION} ${grouped ? 'text-signal' : ''}`}
          >
            {grouped ? '✓ Grouped' : 'Group traffic patterns'}
          </button>
          <button
            type="button"
            onClick={handleExportMarkdown}
            title="Copy the results table as Markdown, for pasting into a PR description or ticket"
            className={TEXT_ACTION}
          >
            {exportCopied ? '✓ Copied!' : 'Export'}
          </button>
          <button
            type="button"
            onClick={handleCopyTable}
            disabled={rowsByCategory.length === 0}
            title="Copy the results table as tab-separated text (pastes into a spreadsheet)"
            className={TEXT_ACTION}
          >
            {tableCopied ? '✓ Copied!' : 'Copy'}
          </button>
          <button
            type="button"
            onClick={handleDownloadCSV}
            disabled={rowsByCategory.length === 0}
            title="Download the results table as a CSV file"
            className={TEXT_ACTION}
          >
            CSV
          </button>
          <button
            type="button"
            onClick={() => onToggleCollapse(run.id)}
            className={TEXT_ACTION}
          >
            {run.isCollapsed ? 'Expand' : 'Collapse'}
          </button>
          <button
            type="button"
            onClick={() => onRemove(run.id)}
            title="Remove this analysis run"
            aria-label="Remove this analysis run"
            className={`${TEXT_ACTION} text-sm hover:text-drop`}
          >
            ✕
          </button>
        </div>
      </div>

      {!run.isCollapsed && (
        <div className="space-y-5">
          {result.warnings?.map((w) => (
            <div key={w} data-testid="verdict-warning" className="border border-amber-500/60 bg-amber-500/10 px-3 py-2 text-xs text-ink-dim">
              {w}
            </div>
          ))}
          {result.skippedPolicies && result.skippedPolicies.length > 0 && (
            <div className="border border-amber-500/60 bg-amber-500/10 px-3 py-2 text-xs text-ink-dim">
              {result.skippedPolicies.length} live policy(ies) not simulated — they use fromNodes/toNodes, which Hubble
              flows can't be matched against: {result.skippedPolicies.join(', ')}. Verdicts ignore their rules.
            </div>
          )}
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
            {result.counts.l7Changed > 0 && (
              <CountChip
                label="L7 changed"
                value={result.counts.l7Changed}
                className={CHANGE_STYLES.L7_CHANGED}
                onClick={() => onOpenHelp('l7 changed')}
              />
            )}
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
          {graphLive || showPausedGraph ? (
            <VerdictGraph
              rows={result.rows}
              selectedNodeId={selectedGraphNode}
              onSelectNode={setSelectedGraphNode}
              hints={VERDICT_GRAPH_HINTS}
            />
          ) : (
            result.rows.length > 0 && (
              <GraphPlaceholder reason="paused" onDraw={() => setShowPausedGraph(true)} />
            )
          )}

          {rowsByCategory.length === 0 &&
            !run.isStreaming &&
            (result.flowsSampled === 0 ? (
              <p className="text-sm text-ink-dim">
                No flows observed for this scope in Hubble's current buffer — nothing to simulate.
              </p>
            ) : result.counts.notSimulated > 0 || result.counts.replySkipped > 0 || result.skippedPolicies?.length || result.counts.unchanged === 0 || result.counts.newlyDropped > 0 || result.counts.newlyAllowed > 0 ? (
              <p className="text-sm text-ink-dim">Inconclusive sample — {result.counts.unchanged === 0 ? 'no unchanged modeled flows' : `${result.counts.unchanged} unchanged modeled flows`}; {result.counts.notSimulated} not simulated, {result.counts.replySkipped} replies skipped. {result.skippedPolicies?.length ? 'Baseline policies were skipped; the comparison is incomplete.' : 'No universal no-regression conclusion can be drawn from this sample.'}</p>
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
                      <td className="px-3 py-2 text-xs text-ink-dim">
                        {row.explanation}
                        {l7Text(row) && (
                          <span data-testid="verdict-l7-rules" className="mt-1 block font-mono text-[0.7rem] text-l7">
                            L7 {l7Text(row)}
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          {/* Not while streaming: the exception re-runs one-shot, which would end the live stream. */}
                          {!run.isStreaming && <WorkloadExceptionMenu row={row} onAddException={onAddException} />}
                          {(row.change === 'NEWLY_DROPPED' || row.change === 'NEWLY_ALLOWED') && !row.l7Request && onAppendRuleToPolicy && (
                            <AddToPolicyButton
                              row={row}
                              policyNamespace={policyNamespace}
                              onAppend={onAppendRuleToPolicy}
                            />
                          )}
                        </div>
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
