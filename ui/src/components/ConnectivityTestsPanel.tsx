import { useEffect, useId, useRef, useState } from 'react'
import {
  fetchServices,
  type ClusterService,
  fetchNamespaces, fetchProbeCapabilities, fetchProbePods, runConnectionProbeStream,
  ConnectionProbeError,
  type ProbePod, type ProbeProtocol, type ConnectionProbeRequest, type ConnectionProbeResponse,
  type ProbeCapabilities, type ProbeImage,
} from '../api'
import { validProbeHost, validProbeNamespace, validProbePort } from '../shared/tcpProbe'
import { candidateFingerprint, connectivityDecision, serviceHostSuggestions, servicePortFor, type ConnectivityDecision } from '../shared/connectivity'
import { SuggestInput } from './SuggestInput'
import type { ProbeStageId } from '../shared/probeStages'
import { Field } from './NamespaceScope'
import { ProbeImagePicker } from './ProbeImagePicker'
import { ProbePath } from './ProbePath'
import { ProbeStepper } from './ProbeStepper'
import { downloadTextFile } from '../shared/tableExport'
import { CountChip, SectionLabel } from './Chips'
import { DecidedBy } from './DecidedBy'
import { CHANGE_STYLES, HEADLINE_CHIP_STYLES, VERDICT_STYLES } from '../shared/chipStyles'
import { noteDisplay, warningDisplay } from '../shared/probeNotes'

const inputClass = 'w-full min-w-0 border border-line bg-void px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none disabled:cursor-not-allowed disabled:opacity-50'
const buttonClass = 'bg-signal px-5 py-2.5 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer'
// The Flows tab's outline button, for secondary actions.
const outlineButtonClass = 'border border-line bg-void px-4 py-2 font-display text-xs font-bold tracking-[0.1em] text-ink-dim uppercase transition-colors hover:border-signal hover:text-signal cursor-pointer'
const errorText = (err: unknown) => err instanceof Error ? err.message : String(err)
type RequestSnapshot = Readonly<ConnectionProbeRequest>
type Attempt = { request: RequestSnapshot; allNamespaces: boolean; submittedAt: string; capabilities: ProbeCapabilities; stages: ProbeStageId[]; response?: ConnectionProbeResponse; error?: string; definiteRejection?: boolean; errorStatus?: number }

export function ConnectivityTestsPanel({ active, candidateYAML, namespace: verdictNamespace, allNamespaces, replaceExisting, resetGeneration = 0, onRunningChange, onOpenHelp, seenServices = [], blockedReason }: {
  active: boolean; candidateYAML: string; namespace: string; allNamespaces: boolean; replaceExisting: boolean; resetGeneration?: number; onRunningChange: (running: boolean) => void; onOpenHelp?: (category: string) => void
  // Why a test can't start right now (the run is still following, or
  // another run's test is in flight); the inputs stay usable.
  blockedReason?: string
  // "ns/name" Services seen in verdict rows: Host suggestions when listing
  // the cluster's Services isn't allowed.
  seenServices?: string[]
}) {
  // One panel per run card: element ids must be unique per panel.
  const uid = useId()
  const ids = { content: `${uid}-content`, capability: `${uid}-capability`, namespaces: `${uid}-namespaces`, hostHelp: `${uid}-host-help` }
  const [expanded, setExpanded] = useState(false)
  const [capability, setCapability] = useState({ enabled: false, message: 'Checking test availability…' })
  const [server, setServer] = useState<ProbeCapabilities>({ enabled: false })
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [sourceNamespace, setSourceNamespace] = useState('')
  const namespace = allNamespaces ? sourceNamespace : verdictNamespace
  const [inventory, setInventory] = useState<{ namespace: string; pods: ProbePod[]; loading: boolean; error: string; excluded?: Record<string, number> }>({ namespace: '', pods: [], loading: false, error: '' })
  const [selection, setSelection] = useState({ namespace: '', uid: '' })
  const [host, setHost] = useState('')
  const [port, setPort] = useState('5432')
  const [protocol, setProtocol] = useState<ProbeProtocol>('TCP')
  const [imageId, setImageId] = useState('')
  const [running, setRunning] = useState(false)
  const [attempt, setAttempt] = useState<Attempt | null>(null)
  const [podRefresh, setPodRefresh] = useState(0)
  const [services, setServices] = useState<{ list: ClusterService[]; forbidden: boolean }>({ list: [], forbidden: false })
  // State is not a synchronous lock. The panel stays mounted across app tabs;
  // never abort or repeat this mutating request just because the view changes.
  const runningRef = useRef(false)
  const mounted = useRef(false)
  useEffect(() => {
    if (runningRef.current) return
    setAttempt(null)
    setSourceNamespace('')
    setSelection({ namespace: '', uid: '' })
    setHost('')
    setPort('5432')
    setProtocol('TCP')
  }, [resetGeneration])

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => {
    if (!active || !expanded) return
    let ignore = false
    setCapability({ enabled: false, message: 'Checking test availability…' })
    fetchProbeCapabilities().then((res) => {
      if (!ignore) setServer(res)
      if (!ignore) setCapability(res.enabled === true
        ? { enabled: true, message: 'Connection tests enabled on this server.' }
        : { enabled: false, message: 'Connection tests are disabled. Start the server with --enable-probes.' })
    }).catch((err) => {
      if (!ignore) setCapability({ enabled: false, message: `Test availability could not be verified: ${errorText(err)}. No test can be started.` })
    })
    return () => { ignore = true }
  }, [active, expanded])

  useEffect(() => {
    if (!active || !expanded || !allNamespaces) return
    let ignore = false
    fetchNamespaces().then((res) => { if (!ignore) setNamespaces(res.namespaces) }).catch(() => {})
    return () => { ignore = true }
  }, [active, expanded, allNamespaces])

  useEffect(() => {
    // A scope change requires a fresh Pod selection, even if the old UID is
    // later seen again. Old async inventories cannot populate the new scope.
    setSelection({ namespace, uid: '' })
  }, [namespace, allNamespaces])

  useEffect(() => {
    if (!active || !expanded || !capability.enabled || !validProbeNamespace(namespace)) return
    let ignore = false
    setInventory((previous) => ({ namespace, pods: previous.namespace === namespace ? previous.pods : [], loading: true, error: '' }))
    fetchProbePods(namespace).then((res) => {
      if (!ignore) setInventory({ namespace, pods: res.pods ?? [], loading: false, error: '', excluded: res.excluded })
    }).catch((err) => {
      if (!ignore) setInventory({ namespace, pods: [], loading: false, error: errorText(err) })
    })
    return () => { ignore = true }
  }, [namespace, allNamespaces, capability.enabled, podRefresh, active, expanded])

  // Host suggestions: the cluster's Services, all namespaces, fetched once
  // per open panel. A failed or forbidden list just means fewer suggestions.
  useEffect(() => {
    if (!active || !expanded || !capability.enabled) return
    let ignore = false
    fetchServices().then((res) => {
      if (!ignore) setServices({ list: res.services ?? [], forbidden: !!res.forbidden })
    }).catch(() => {})
    return () => { ignore = true }
  }, [active, expanded, capability.enabled])

  // The catalog is the server's; an id it no longer offers falls back to its
  // default (first) entry rather than sending something it would reject.
  const images = server.images ?? []
  const selectedImage = images.find((image) => image.id === imageId) ?? images[0]
  const currentInventory = inventory.namespace === namespace && validProbeNamespace(namespace)
  const pods = currentInventory ? inventory.pods : []
  const selectedPod = selection.namespace === namespace ? pods.find((pod) => pod.uid === selection.uid) : undefined
  const imageSupports = (p: ProbeProtocol) => !selectedImage || selectedImage.protocols.includes(p)
  const protocolSupported = (!server.protocols || server.protocols.includes(protocol)) && imageSupports(protocol)
  const podPlaceholder = !capability.enabled ? 'Enable connectivity tests first' : !validProbeNamespace(namespace) ? 'Select a source namespace' : inventory.loading ? 'Loading eligible Pods…' : inventory.error ? 'Could not load Pods' : !pods.length ? 'No eligible Pods found' : 'Select an existing Pod'
  const excluded = currentInventory ? Object.entries(inventory.excluded ?? {}) : []
  const ready = !blockedReason && active && expanded && capability.enabled && protocolSupported && candidateYAML.trim() && selectedPod && validProbeHost(host) && validProbePort(port) && !inventory.loading
  const stale = !!attempt && (attempt.request.namespace !== namespace || attempt.allNamespaces !== allNamespaces ||
    (!inventory.loading && attempt.request.uid !== selectedPod?.uid) || attempt.request.host !== host || attempt.request.port !== Number(port) ||
    attempt.request.protocol !== protocol || attempt.request.candidateYAML !== candidateYAML || attempt.request.replaceExisting !== replaceExisting ||
    attempt.request.candidateNamespace !== (allNamespaces ? '' : verdictNamespace) || attempt.request.imageId !== selectedImage?.id)

  function pickImage(image: ProbeImage) {
    setImageId(image.id)
    if (!image.protocols.includes(protocol)) setProtocol(image.protocols[0])
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!ready || runningRef.current || !selectedPod) return
    runningRef.current = true
    const request: RequestSnapshot = Object.freeze({ namespace, pod: selectedPod.name, uid: selectedPod.uid, host, port: Number(port), protocol, candidateYAML, replaceExisting, candidateNamespace: allNamespaces ? '' : verdictNamespace, ...(selectedImage ? { imageId: selectedImage.id } : {}) })
    const snapshot: Attempt = { request, allNamespaces, submittedAt: new Date().toISOString(), capabilities: { ...server }, stages: [] }
    const confirmed = window.confirm(
      `Run one bounded ${protocol === 'UDP' ? 'UDP datagram with a fixed payload (27 bytes: guardbee-connectivity-probe)' : 'TCP connection'} from existing Pod ${namespace}/${selectedPod.name} (UID ${selectedPod.uid}) to ${host}:${port}?\n\n` +
      (selectedImage ? `Probe image: ${selectedImage.name} (${selectedImage.image})\n\n` : '') +
      (server.context || server.apiServer ? `Cluster: ${server.context ?? 'unknown context'}${server.apiServer ? ` · ${server.apiServer}` : ''}\n\n` : '') +
      'This adds an ephemeral container, changing the Pod spec but not its labels. The process exits, but its spec entry remains until normal Pod replacement. GuardBee does NOT automatically restart or delete the Pod.\n\n' +
      'Traffic runs against current policy. The loaded candidate is simulated separately, never applied. No shell, editable payload, or arbitrary commands. ' +
      (protocol === 'UDP' ? 'Generating a UDP datagram does not prove reachability or delivery.' : 'A TCP connection is not database authentication.')
    )
    if (!confirmed) { runningRef.current = false; return }
    setRunning(true)
    onRunningChange(true)
    setAttempt(snapshot)
    const onStage = (stage: ProbeStageId) => {
      if (mounted.current) setAttempt((current) => current?.submittedAt === snapshot.submittedAt ? { ...current, stages: [...current.stages, stage] } : current)
    }
    try {
      const response = await runConnectionProbeStream(request, onStage)
      if (mounted.current) setAttempt((current) => ({ ...(current ?? snapshot), response }))
    } catch (err) {
      if (mounted.current) setAttempt((current) => ({ ...(current ?? snapshot), error: errorText(err), definiteRejection: err instanceof ConnectionProbeError && err.definiteRejection, errorStatus: err instanceof ConnectionProbeError ? err.status : undefined }))
    } finally {
      runningRef.current = false
      onRunningChange(false)
      if (mounted.current) setRunning(false)
    }
  }

  return (
    <section aria-label="Connectivity tests" className="mt-6 min-w-0 border border-line bg-panel">
      <button type="button" aria-expanded={expanded} aria-controls={ids.content} onClick={() => setExpanded(!expanded)} className="flex w-full cursor-pointer flex-wrap items-center justify-between gap-3 p-5 text-left hover:bg-void/30">
        <span><span className="block text-[0.65rem] font-semibold tracking-[0.18em] text-signal uppercase">Connectivity tests</span><span className="mt-1 block text-xs text-ink-dim">Test a specific connection against this run's candidate.</span></span>
        <span className="flex items-center gap-3"><Badge>Bounded · opt-in</Badge><span aria-hidden="true" className="text-ink-dim">{expanded ? '−' : '+'}</span></span>
      </button>
      <div id={ids.content} hidden={!expanded} className="min-w-0 space-y-5 border-t border-line p-5">
        <div className="flex flex-wrap items-center gap-2 text-xs text-ink-dim" aria-label="Current candidate context">
          <Badge>{candidateYAML.trim() ? `Candidate ${candidateFingerprint(candidateYAML)}` : 'No candidate loaded'}</Badge>
          <Badge>{allNamespaces ? 'All namespaces' : `Source namespace: ${namespace || 'not selected'}`}</Badge>
          <Badge>{replaceExisting ? 'Replace matching live policies' : 'Additive · keep live policies'}</Badge>
          {(server.context || server.apiServer) && <Badge>Cluster: {server.context ?? 'unknown context'}{server.apiServer && ` · ${server.apiServer}`}</Badge>}
        </div>
        {!candidateYAML.trim() && <p role="status" className="text-sm text-ink-dim">This run has no candidate to test against.</p>}
        {blockedReason && !running && <p role="status" className="text-sm text-ink-dim">{blockedReason}</p>}
        <p id={ids.capability} role="status" className={capability.enabled ? 'sr-only' : 'break-words text-xs text-ink-dim'}>{capability.message}</p>
        {!capability.enabled && <div className="space-y-2 border border-line bg-void/40 p-4 text-sm text-ink-dim" aria-label="Connectivity enablement">
          <h3 className="font-display font-bold text-ink">Connectivity tests require explicit server opt-in</h3>
          <code className="block whitespace-pre-wrap break-all text-xs text-ink">./guardbee ui --enable-probes</code>
          <p className="text-xs">Offers the built-in vetted probe images; <code>--probe-images-file</code> replaces that list. Needs the separate probes RBAC.</p>
        </div>}
        <form aria-label="Connection test configuration" onSubmit={handleSubmit} className="min-w-0 space-y-4">
          <fieldset disabled={running || !capability.enabled} className="min-w-0 space-y-4">
            {images.length > 0 && selectedImage && <SectionLabel>Probe image</SectionLabel>}
            {images.length > 0 && selectedImage && <ProbeImagePicker images={images} value={selectedImage.id} protocol={protocol} onChange={pickImage} />}
            <SectionLabel>Target</SectionLabel>
            <div className="grid min-w-0 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {allNamespaces && <Field label="Source namespace">
                <input value={sourceNamespace} list={ids.namespaces} required maxLength={63} pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?" className={inputClass} placeholder="Choose a namespace" onChange={(e) => setSourceNamespace(e.target.value)} />
                <datalist id={ids.namespaces}>{namespaces.map((ns) => <option key={ns} value={ns} />)}</datalist>
              </Field>}
              <Field label="Source Pod"><select aria-label="Source Pod" value={selectedPod?.uid ?? ''} required className={inputClass} onChange={(e) => setSelection({ namespace, uid: e.target.value })}>
                <option value="">{podPlaceholder}</option>
                {pods.map((pod) => <option key={pod.uid} value={pod.uid}>{pod.name}</option>)}
              </select></Field>
              <Field label="Host or IP"><SuggestInput
                value={host}
                multi={false}
                suggestions={serviceHostSuggestions(services.list, seenServices, namespace)}
                placeholder="db.myapp.svc.cluster.local"
                className={inputClass}
                inputProps={{ required: true, maxLength: 253, 'aria-describedby': ids.hostHelp, 'aria-invalid': !!host && !validProbeHost(host) }}
                onChange={(v) => {
                  setHost(v)
                  // Picking a known Service fills its port for this protocol.
                  const p = servicePortFor(services.list, v, protocol)
                  if (p) setPort(p)
                }}
              /></Field>
              <Field label="Port"><input value={port} required inputMode="numeric" maxLength={5} pattern="[0-9]{1,5}" aria-invalid={!validProbePort(port)} className={inputClass} onChange={(e) => setPort(e.target.value)} /></Field>
              <Field label="Protocol"><select value={protocol} className={inputClass} onChange={(e) => setProtocol(e.target.value as ProbeProtocol)}>{(['TCP', 'UDP'] as const).map((p) => <option key={p} value={p} disabled={!!server.protocols && !server.protocols.includes(p) || !imageSupports(p)}>{p}{!imageSupports(p) && selectedImage ? ` (not in ${selectedImage.name})` : ''}</option>)}</select></Field>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-ink-dim">
              <p id={ids.hostHelp}>{protocol === 'UDP' ? 'Sends one bounded datagram with a fixed payload (27 bytes); delivery is never proven.' : 'Opens one bounded TCP connection; not an application login.'} Host: an IP address or a Kubernetes Service name ({services.forbidden ? 'suggestions are Services seen in flows: GuardBee may not list Services' : 'pick one of the cluster\'s Services to fill its port'}); for an external site, use its IP.</p>
              <button type="button" className="cursor-pointer text-signal disabled:opacity-40" disabled={!validProbeNamespace(namespace) || inventory.loading} onClick={() => setPodRefresh((value) => value + 1)}>Refresh running Pods</button>
            </div>
            {currentInventory && inventory.error && <p role="alert" className="break-words text-sm text-drop">Could not list running Pods: {inventory.error}</p>}
            {capability.enabled && currentInventory && !inventory.loading && !inventory.error && !pods.length && <p role="status" className="text-xs text-ink-dim">No eligible Pods here. System, host-network, process-sharing, unready Pods, and Pods with a pending GuardBee container are excluded.</p>}
            {excluded.length > 0 && <details open={!pods.length} className="text-xs text-ink-dim"><summary className="cursor-pointer">{excluded.reduce((total, [, count]) => total + count, 0)} Pods excluded</summary><ul className="mt-2 space-y-1">{excluded.map(([reason, count]) => <li key={reason}>{reason} ({count})</li>)}</ul></details>}
          </fieldset>
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-line pt-4">
            <p className="text-xs text-ink-dim">Adds an ephemeral container to the Pod · you confirm first</p>
            <button type="submit" disabled={!ready || running} aria-describedby={ids.capability} className={buttonClass}>{running ? 'Running connection test…' : 'Review & run connection test'}</button>
          </div>
        </form>
        {attempt && <section aria-label="Submitted connection test" className="rise-in min-w-0 space-y-4 border-t border-line pt-5 break-words">
          <div className="flex flex-wrap items-center gap-2"><Badge>{attempt.request.protocol}</Badge><Badge>{attempt.request.namespace}/{attempt.request.pod}</Badge><span aria-hidden="true" className="text-ink-faint">→</span><Badge>{attempt.request.host} · port {attempt.request.port}</Badge>{attempt.request.imageId && <Badge>{attempt.capabilities.images?.find((image) => image.id === attempt.request.imageId)?.name ?? attempt.request.imageId}</Badge>}</div>
          {stale && <p role="status" className="text-xs text-allow">Inputs changed since this test. Results are stale and refer only to the submitted Pod, target, image, scope, and candidate snapshot, not the current Verdict form.</p>}
          {(running || attempt.stages.length > 0) && <SectionLabel>Progress</SectionLabel>}
          {(running || attempt.stages.length > 0) && <ProbeStepper reached={attempt.stages} run={running ? 'running' : attempt.error !== undefined ? 'failed' : 'done'} />}
          {running && <p role="status" className="text-xs text-ink-dim">Switching tabs does not cancel or repeat this test.</p>}
          {attempt.response && <SectionLabel>Result</SectionLabel>}
          {attempt.response && <ConnectionResult response={attempt.response} request={attempt.request} onOpenHelp={onOpenHelp} />}
          {attempt.error !== undefined && <div role="alert" className="space-y-2 border border-drop/40 bg-drop/10 p-4 text-sm text-drop">
            <p className="font-bold">{attempt.definiteRejection ? 'Test not started' : 'Predicted candidate: INCONCLUSIVE'}</p><p>{attempt.error}</p>
            {attempt.definiteRejection ? <p>The server rejected this request before adding an ephemeral container. Fix the error before running a new confirmed test.</p> : <p>An ephemeral container may already have been added to the original Pod {attempt.request.namespace}/{attempt.request.pod} (UID {attempt.request.uid}). Inspect that Pod before deciding to run again. GuardBee does not automatically retry, restart, or delete it.</p>}
          </div>}
          {!running && <div className="flex flex-wrap gap-4">
            {/* schemaVersion 2: response.notes ({code, text}) replaced notices (strings). */}
            <button type="button" className={outlineButtonClass} onClick={() => downloadTextFile(`guardbee-connectivity-${candidateFingerprint(attempt.request.candidateYAML)}.json`, JSON.stringify({ schemaVersion: 2, ...attempt }, null, 2), 'application/json')}>Download test report (JSON)</button>
            <button type="button" className={outlineButtonClass} onClick={() => setAttempt(null)}>Clear completed test</button>
          </div>}
          <details><summary className="cursor-pointer text-xs text-ink-dim">Submitted candidate snapshot {candidateFingerprint(attempt.request.candidateYAML)}</summary>
            <p className="mt-3 text-xs text-ink-dim">Original Pod UID: {attempt.request.uid} · {attempt.allNamespaces ? 'All namespaces' : 'Single namespace'}</p>
            <pre className="mt-3 whitespace-pre-wrap break-words text-xs text-ink-dim">{attempt.request.candidateYAML}</pre>
          </details>
        </section>}
      </div>
    </section>
  )
}

function Badge({ children }: { children: React.ReactNode }) {
  return <span className="max-w-full break-words border border-line bg-void/50 px-2 py-1 font-mono text-[0.65rem] text-ink-dim">{children}</span>
}

const decisionTone: Record<ConnectivityDecision, string> = { ALLOWED: 'text-unchanged', BLOCKED: 'text-drop', INCONCLUSIVE: 'text-ink-dim' }
const decisionChip = (d: boolean | undefined) => d === true ? <span className="text-unchanged">✓ allowed</span> : d === false ? <span className="text-drop">✕ blocked</span> : <span className="text-ink-faint">? unknown</span>

function Decision({ label, decision }: { label: string; decision: ConnectivityDecision }) {
  return <div className="space-y-0.5"><p className="text-[0.65rem] tracking-[0.12em] text-ink-dim uppercase">{label}</p><p className={`font-display text-sm font-bold ${decisionTone[decision]}`}>{decision}</p></div>
}

// The headline banner, in the same words and colors as Verdict's own
// "would BREAK" banner, so both answers to "is this candidate safe?" read alike.
function ResultBanner({ baseline, candidate }: { baseline: ConnectivityDecision; candidate: ConnectivityDecision }) {
  if (candidate === 'INCONCLUSIVE' || baseline === 'INCONCLUSIVE') return null
  if (baseline === 'ALLOWED' && candidate === 'BLOCKED') return <p className="border border-drop/40 bg-drop/10 px-4 py-3 text-sm font-semibold text-drop">This connection would BREAK if the candidate merged as-is.</p>
  if (baseline === 'BLOCKED' && candidate === 'ALLOWED') return <p className="border border-allow/40 bg-allow/10 px-4 py-3 text-sm font-semibold text-allow">The candidate would newly ALLOW this connection.</p>
  if (candidate === 'ALLOWED') return <p className="border border-unchanged/40 bg-unchanged/10 px-4 py-3 text-sm font-semibold text-unchanged">Still allowed with the candidate.</p>
  return <p className="border border-line bg-void/40 px-4 py-3 text-sm font-semibold text-ink-dim">Blocked today and with the candidate.</p>
}

// A small square chip for run metadata; copyable ones copy their full value.
function MetaChip({ icon, label, title, copy }: { icon: string; label: string; title?: string; copy?: string }) {
  const content = <>{icon && <span aria-hidden="true">{icon}</span>}<span className="truncate">{label}</span></>
  const className = 'flex min-w-0 max-w-full items-center gap-1.5 border border-line bg-void/50 px-2 py-1 font-mono text-[0.65rem] text-ink-dim'
  return copy
    ? <button type="button" title={`${title ?? copy} — click to copy`} onClick={() => { void navigator.clipboard?.writeText(copy) }} className={`${className} cursor-pointer hover:border-signal hover:text-signal`}>{content}</button>
    : <span title={title} className={className}>{content}</span>
}

const th = 'px-3 py-2 text-[0.65rem] font-semibold tracking-[0.1em] text-ink-dim uppercase'
const td = 'px-3 py-2 font-mono text-xs text-ink'

function ConnectionResult({ response, request, onOpenHelp }: { response: ConnectionProbeResponse; request: RequestSnapshot; onOpenHelp?: (category: string) => void }) {
  const simulation = response.simulation
  const protocolMatches = !response.protocol || response.protocol === request.protocol
  const baseline = protocolMatches ? connectivityDecision(response, 'baselineAllowed') : 'INCONCLUSIVE'
  const candidate = protocolMatches ? connectivityDecision(response, 'candidateAllowed') : 'INCONCLUSIVE'
  // Warnings are this attempt's own problems and stay visible; notes are the
  // caveats every attempt carries and live behind a disclosure, so the one
  // thing that went wrong isn't buried among them.
  const warnings = [...new Set([...(response.warnings ?? []), ...(simulation?.skippedPolicies ?? []).map((policy) => `Baseline policy skipped: ${policy}. Simulation does not account for it.`)])]
  const notes = response.notes ?? []
  const flows = response.flows ?? []
  const rows = simulation?.rows ?? []
  const events = flows.reduce((total, flow) => total + (flow.count ?? 1), 0)
  const changeCount = (change: string) => rows.filter((row) => row.change === change).length
  const transport = request.protocol === 'UDP' ? 'Traffic generation' : 'Observed TCP transport'
  const outcome = response.outcome ?? 'inconclusive'
  const imageName = response.image?.split('@')[0].split('/').pop()
  return <div className="min-w-0 space-y-4" aria-live="polite">
    <ResultBanner baseline={baseline} candidate={candidate} />
    <section aria-label="Candidate prediction" className="grid min-w-0 items-center gap-4 border border-line bg-void/40 p-4 md:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
      <div className="min-w-0 space-y-3">
        <div><p className="text-[0.65rem] tracking-[0.12em] text-ink-dim uppercase">Predicted with candidate</p><h3 className={`mt-1 font-display text-2xl font-bold ${decisionTone[candidate]}`}>{candidate}</h3></div>
        <div className="flex flex-wrap gap-5"><Decision label="Baseline model" decision={baseline} /><Decision label="With candidate" decision={candidate} /></div>
      </div>
      {/* Below ~30rem the drawing would shrink its labels past legibility;
          it scrolls inside its own box instead, never the page. */}
      <div className="min-w-0 overflow-x-auto"><ProbePath source={`${request.namespace}/${request.pod}`} destination={flows[0]?.destination || request.host} l4={`${request.protocol} ${request.port}`} baseline={baseline} candidate={candidate} /></div>
      {candidate === 'INCONCLUSIVE' && <p className="text-sm text-ink-dim md:col-span-2">{warnings.find((warning) => warning.startsWith('Simulation inconclusive:')) ?? warnings[0] ?? (!flows.length ? 'No matching Hubble evidence was captured for this attempt.' : 'The sample does not provide one complete, consistent candidate decision. Expand the evidence below for details.')}</p>}
    </section>
    <div className="flex flex-wrap items-center gap-2">
      <span title={`${response.message} — ${request.protocol === 'UDP' ? 'a generated datagram does not prove reachability or delivery.' : 'connected proves TCP transport only, not application authentication; failure does not by itself prove policy denial.'}`} className={`border px-2.5 py-1 text-xs font-medium ${outcome === 'connected' || outcome === 'generated' ? VERDICT_STYLES.FORWARDED : outcome === 'failed' ? VERDICT_STYLES.DROPPED : 'border-line text-ink-dim'}`}>{transport}: {outcome}</span>
      {/* Distinct flows, like the "N flows" chip beside them: one connection's
          trace events are one row here, not N separate regressions. */}
      {changeCount('NEWLY_DROPPED') > 0 && <CountChip label="newly dropped" value={changeCount('NEWLY_DROPPED')} className={HEADLINE_CHIP_STYLES.NEWLY_DROPPED} filled onClick={() => onOpenHelp?.('newly dropped')} />}
      {changeCount('NEWLY_ALLOWED') > 0 && <CountChip label="newly allowed" value={changeCount('NEWLY_ALLOWED')} className={HEADLINE_CHIP_STYLES.NEWLY_ALLOWED} filled onClick={() => onOpenHelp?.('newly allowed')} />}
      {changeCount('UNCHANGED') > 0 && <CountChip label="unchanged" value={changeCount('UNCHANGED')} className={CHANGE_STYLES.UNCHANGED} onClick={() => onOpenHelp?.('unchanged')} />}
      {simulation && simulation.counts.notSimulated > 0 && <CountChip label="not simulated" value={simulation.counts.notSimulated} className="border-line-bright bg-panel-raised text-ink-dim" onClick={() => onOpenHelp?.('not simulated')} />}
      <span className="border border-line px-2.5 py-1 text-xs text-ink-dim"><span className="font-semibold text-ink">{flows.length}</span> {flows.length === 1 ? 'flow' : 'flows'}{events > flows.length && <> · <span className="font-semibold text-ink">{events}</span> Hubble events</>}</span>
    </div>
    <div aria-label="Run details" className="flex min-w-0 flex-wrap gap-2">
      {response.durationMs !== undefined && <MetaChip icon="" label={`${(response.durationMs / 1000).toFixed(1)} s`} title={response.startedAt ? `Started ${response.startedAt}` : undefined} />}
      {response.image && <MetaChip icon={response.image.includes('@sha256:') ? '' : '⚠'} label={imageName ?? response.image} title={response.image} copy={response.image} />}
      {response.containerName && <MetaChip icon="⧉" label={response.containerName} title="Ephemeral container, kept until normal Pod replacement" copy={response.containerName} />}
      {(response.context || response.apiServer) && <MetaChip icon="⎈" label={response.context ?? 'unknown context'} title={`Cluster: ${response.context ?? 'unknown context'}${response.apiServer ? ` · ${response.apiServer}` : ''}`} />}
    </div>
    {warnings.length > 0 && <ul aria-label="Attempt warnings" className="space-y-1.5">{warnings.map((warning, i) => {
      const w = warningDisplay(warning)
      return <li key={i} className="flex gap-2 border border-allow/40 bg-allow/5 px-3 py-2 text-xs text-allow"><span aria-hidden="true">⚠</span><span className="min-w-0"><span className="font-semibold">Warning: {w.title}</span>{w.detail !== w.title && <span className="block text-ink-dim">{w.detail}</span>}</span></li>
    })}</ul>}
    <details className="border border-line"><summary className="cursor-pointer px-3 py-2 text-[0.65rem] font-semibold tracking-[0.1em] text-ink-dim uppercase">Evidence & limitations · {flows.length} distinct {flows.length === 1 ? 'flow' : 'flows'}{events > flows.length && ` (${events} Hubble events)`} · {rows.length} simulated {rows.length === 1 ? 'row' : 'rows'}{notes.length > 0 && ` · ${notes.length} notes`}</summary>
      <div className="min-w-0 space-y-4 border-t border-line p-3 text-xs text-ink-dim">
        <section aria-label="Observed Hubble flows" className="min-w-0 space-y-2"><h4 className={th + ' px-0'}>Observed under current policy</h4>
          {!flows.length ? <p>No Hubble flows observed. Observation is unavailable or inconclusive.</p> : <div className="overflow-x-auto border border-line"><table className="w-full min-w-[640px] text-left text-sm">
            <thead className="border-b border-line bg-panel-raised"><tr>{['Verdict', 'Source', 'Destination', 'Port', 'Direction', 'Seen', 'Decided by'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{flows.map((flow, i) => <tr key={i} className="hover:bg-panel-raised/60" title={flow.time}>
              <td className="px-3 py-2"><span className={`border px-2 py-0.5 text-[0.65rem] font-semibold ${VERDICT_STYLES[flow.verdict] ?? 'border-line-bright bg-panel-raised text-ink-dim'}`}>{flow.verdict}</span>{flow.dropReason && <span className="ml-1 text-[0.65rem] text-drop">{flow.dropReason}</span>}</td>
              <td className={td}>{flow.source}</td><td className={td}>{flow.destination}</td><td className={td}>{flow.l4}</td>
              <td className="px-3 py-2 text-xs text-ink-dim">{flow.direction ?? '—'}</td>
              <td className="px-3 py-2 text-xs text-ink-faint">{(flow.count ?? 1) > 1 ? `×${flow.count} events` : '—'}</td>
              <td className="px-3 py-2"><DecidedBy flow={flow} /></td>
            </tr>)}</tbody>
          </table></div>}
        </section>
        <section aria-label="Candidate simulation" className="min-w-0 space-y-2"><h4 className={th + ' px-0'}>Candidate simulation evidence</h4>
          {!rows.length ? <p>No modeled result rows; candidate impact is inconclusive.</p> : <div className="overflow-x-auto border border-line"><table className="w-full min-w-[640px] text-left text-sm">
            <thead className="border-b border-line bg-panel-raised"><tr>{['Change', 'Source', 'Destination', 'Port', 'Baseline', 'Candidate', 'Seen'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-line">{rows.map((row, i) => <tr key={i} className="hover:bg-panel-raised/60" title={row.explanation}>
              <td className="px-3 py-2"><span className={`border px-2 py-0.5 text-[0.65rem] font-semibold ${CHANGE_STYLES[row.change]}`}>{row.change}</span></td>
              <td className={td}>{row.source}</td><td className={td}>{row.destination}</td><td className={td}>{row.protocol}:{row.port}</td>
              <td className="px-3 py-2 text-xs">{decisionChip(row.baselineAllowed)}</td><td className="px-3 py-2 text-xs">{decisionChip(row.candidateAllowed)}</td>
              <td className="px-3 py-2 text-xs text-ink-faint">{row.count > 1 ? `×${row.count} events` : '—'}</td>
            </tr>)}</tbody>
          </table></div>}
        </section>
        {notes.length > 0 && <section aria-label="Test notes" className="space-y-1"><h4 className={th + ' px-0'}>About this test</h4>{notes.map((note, i) => {
          const n = noteDisplay(note)
          return <details key={i} className="group"><summary className="flex cursor-pointer list-none items-center gap-2 py-0.5 hover:text-ink"><span aria-hidden="true" className="w-4 text-center text-signal">{n.icon}</span><span>{n.title}</span><span aria-hidden="true" className="text-ink-faint group-open:rotate-90">›</span></summary><p className="mt-1 ml-6 text-ink-faint">{note.text}</p></details>
        })}</section>}
      </div>
    </details>
  </div>
}
